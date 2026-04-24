// cmd/coverage-diff scrapes the awesome-flipperzero upstream lists for
// tool/verb names and cross-references them against PromptZero's registered
// tool registry (internal/tools).  It emits a markdown gap report listing
// candidates we don't yet expose, grouped by upstream repository.
//
// Usage:
//
//	coverage-diff [flags]
//
// Flags:
//
//	--markdown       output markdown report (default: true; flag available for
//	                 scripting clarity)
//	--no-cache       bypass the local HTTP response cache in ${TMPDIR}
//	--out-of-scope   path to the YAML allowlist of intentionally-skipped tokens
//	                 (default: docs/coverage/out-of-scope.yaml)
//
// The exit code is 0 even when gaps are found — gaps are informational.
// A non-zero exit indicates a fatal setup error (e.g. all fetches failed).
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/tools"
)

func main() {
	noCache := flag.Bool("no-cache", false, "bypass local HTTP response cache")
	outScopePath := flag.String("out-of-scope", "docs/coverage/out-of-scope.yaml",
		"path to out-of-scope allowlist YAML (tokens subtracted before reporting)")
	// --markdown is always-on; the flag exists so scripts can pass it explicitly.
	_ = flag.Bool("markdown", true, "output markdown report (always enabled)")
	flag.Parse()

	// Build the canonical tool-name set from the live registry.
	// All init() functions have run by the time main() starts, so
	// tools.Names() reflects the full production registry.
	toolNames := tools.Names()

	// Load out-of-scope allowlist (absence is silently OK).
	blocked := loadOutOfScope(*outScopePath)

	// Fetch and classify each upstream source.
	var results []RepoResult
	fetchFailed := 0
	for _, src := range upstreamSources {
		content, err := FetchContent(src.URL, !*noCache)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", src.Name, err)
			results = append(results, RepoResult{Source: src, Err: err})
			fetchFailed++
			continue
		}
		toks := ExtractTokens([]byte(content))
		matched, gaps := classify(toks, toolNames, blocked)
		results = append(results, RepoResult{
			Source:  src,
			Tokens:  toks,
			Matched: matched,
			Gaps:    gaps,
		})
	}

	// Abort only when every single source failed.
	if fetchFailed == len(upstreamSources) {
		fmt.Fprintln(os.Stderr, "error: all upstream fetches failed; cannot produce a report")
		os.Exit(1)
	}

	report := RenderMarkdown(results, time.Now().Format("2006-01-02"))
	fmt.Print(report)
}

// classify splits tokens into matched (known tools) and gaps (unknown
// candidates). It accepts the blocked allowlist so out-of-scope tokens are
// subtracted before either bucket is populated.
//
// Matching uses canonical comparison: both the upstream token and every tool
// name are passed through canonicalize before the strings.Contains check.
// A token is "matched" when at least one canonical tool name contains it as
// a substring (or equals it exactly).
func classify(tokens, toolNames []string, blocked map[string]struct{}) (matched, gaps []string) {
	// Pre-compute canonical tool names once.
	canonTools := make([]string, 0, len(toolNames))
	for _, n := range toolNames {
		canonTools = append(canonTools, canonicalize(n))
	}

	seen := make(map[string]struct{})
	for _, tok := range tokens {
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}

		if _, skip := blocked[tok]; skip {
			continue
		}
		if matchesAnyTool(tok, canonTools) {
			matched = append(matched, tok)
		} else {
			gaps = append(gaps, tok)
		}
	}
	sort.Strings(matched)
	sort.Strings(gaps)
	return matched, gaps
}

// matchesAnyTool returns true when canonical token c is found as a substring
// of (or exactly equals) any canonical tool name in the registry.
func matchesAnyTool(c string, canonTools []string) bool {
	for _, ct := range canonTools {
		if strings.Contains(ct, c) {
			return true
		}
	}
	return false
}

// loadOutOfScope reads the YAML allowlist at path and returns the canonical
// forms of every listed token. If the file is absent or unreadable the
// function returns an empty map (absence is silently OK — operators create
// the file incrementally as they triage gaps).
//
// The expected format is a simple YAML list:
//
//	tokens:
//	  - some_token
//	  - another_token
func loadOutOfScope(path string) map[string]struct{} {
	result := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil {
		return result // absent or unreadable — silently OK
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// Accept list items starting with "- ".
		if !strings.HasPrefix(line, "-") {
			continue
		}
		tok := canonicalize(strings.TrimSpace(strings.TrimPrefix(line, "-")))
		if tok != "" {
			result[tok] = struct{}{}
		}
	}
	return result
}
