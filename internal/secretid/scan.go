// SPDX-License-Identifier: AGPL-3.0-or-later

// scan.go — bulk secret scanning over arbitrary text. Where Identify classifies
// a single captured string, Scan is the real loot-triage workflow: hand it a
// config file, an env dump, a log, or a source blob and it extracts every
// candidate secret and routes each through Identify. It is the secretid
// analogue of running the whole credential-decoder suite over a haystack.
//
// Conservative by construction: it extracts only candidates matching
// high-signal structural patterns (PEM blocks, JWTs, AWS key IDs, GitHub
// tokens, Google keys, and the documented vendor-token prefixes), then keeps a
// finding only when Identify actually recognises the candidate. So a reported
// finding is always a format match, never an entropy guess; the secret value
// itself is redacted in the output.

package secretid

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Finding is one located, identified secret.
type Finding struct {
	// Line is the 1-based line the secret starts on.
	Line int `json:"line"`
	// Type / Category / Validated / Valid / Detail mirror the Identify Result.
	Type      string `json:"type"`
	Category  string `json:"category,omitempty"`
	Validated bool   `json:"validated"`
	Valid     bool   `json:"valid,omitempty"`
	Detail    string `json:"detail,omitempty"`
	// Redacted is a safe preview (prefix + length) — never the full secret.
	Redacted string `json:"redacted"`
}

// ScanResult is the outcome of a Scan.
type ScanResult struct {
	Findings []Finding `json:"findings"`
	// Truncated is true when the candidate cap was hit (no silent capping).
	Truncated bool   `json:"truncated,omitempty"`
	Note      string `json:"note"`
}

// maxFindings bounds output on pathological input; truncation is surfaced.
const maxFindings = 1000

// candidateRes are the high-signal extractors. Order is not significant —
// overlapping matches are de-duplicated by start offset, keeping the longest.
var candidateRes = buildCandidateRes()

func buildCandidateRes() []*regexp.Regexp {
	res := []*regexp.Regexp{
		// PEM / ASCII-armor block (multi-line, non-greedy to the first END).
		regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]+-----.*?-----END [A-Z0-9 ]+-----`),
		// JWT: three base64url segments.
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`),
		// AWS access key ID: documented 4-char type prefix + 16 base32 chars.
		regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA|A3T[A-Z0-9])[A-Z0-9]{16}\b`),
		// GitHub tokens (classic prefixes + fine-grained).
		regexp.MustCompile(`\bgh[opusr]_[A-Za-z0-9]{36,255}\b`),
		regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{30,255}\b`),
		// Google API key / OAuth access token.
		regexp.MustCompile(`\bAIza[A-Za-z0-9_\-]{35}\b`),
		regexp.MustCompile(`\bya29\.[A-Za-z0-9_\-]{20,}`),
	}
	// Vendor-prefix tokens, built from the documented prefix table so the two
	// stay in sync. Each prefix is followed by a run of token characters.
	var alt []string
	for _, v := range vendorPrefixes {
		alt = append(alt, regexp.QuoteMeta(v.prefix))
	}
	res = append(res, regexp.MustCompile(`(?:`+strings.Join(alt, "|")+`)[A-Za-z0-9._/+=\-]{6,}`))
	return res
}

// Scan extracts and identifies every recognisable secret in text, returning the
// findings in source order (de-duplicated, secret values redacted).
func Scan(text string) *ScanResult {
	res := &ScanResult{
		Findings: []Finding{},
		Note: "Format-confirmed matches only (each routed through secret_identify); secret values are " +
			"redacted. Absence of a finding is not proof a blob is clean — only the high-signal patterns " +
			"are extracted.",
	}
	if text == "" {
		return res
	}
	lineStarts := lineOffsets(text)

	// Collect candidate spans, then de-duplicate overlaps keeping the longest.
	type span struct{ start, end int }
	var spans []span
	for _, re := range candidateRes {
		for _, m := range re.FindAllStringIndex(text, -1) {
			spans = append(spans, span{m[0], m[1]})
		}
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].start != spans[j].start {
			return spans[i].start < spans[j].start
		}
		return spans[i].end > spans[j].end // longer first at same start
	})

	lastEnd := -1
	for _, s := range spans {
		if s.start < lastEnd {
			continue // overlaps a finding already taken
		}
		cand := text[s.start:s.end]
		r := Identify(cand)
		if !r.Matched {
			continue
		}
		lastEnd = s.end
		if len(res.Findings) >= maxFindings {
			res.Truncated = true
			break
		}
		res.Findings = append(res.Findings, Finding{
			Line:      lineForOffset(lineStarts, s.start),
			Type:      r.Type,
			Category:  r.Category,
			Validated: r.Validated,
			Valid:     r.Valid,
			Detail:    r.Detail,
			Redacted:  redact(cand),
		})
	}
	return res
}

// lineOffsets returns the byte offset at which each line starts.
func lineOffsets(text string) []int {
	offs := []int{0}
	for i := 0; i < len(text); i++ {
		if text[i] == '\n' {
			offs = append(offs, i+1)
		}
	}
	return offs
}

// lineForOffset maps a byte offset to its 1-based line number.
func lineForOffset(starts []int, off int) int {
	// starts is ascending; find the last start <= off.
	lo, hi := 0, len(starts)-1
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if starts[mid] <= off {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo + 1
}

// redact returns a safe preview: the first few characters plus the length,
// never the full secret. A PEM block is reduced to its BEGIN line.
func redact(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 { // PEM / multi-line
		head := strings.TrimSpace(s[:i])
		return fmt.Sprintf("%s … (%d bytes)", head, len(s))
	}
	const keep = 4
	if len(s) <= keep {
		return fmt.Sprintf("… (%d chars)", len(s))
	}
	return fmt.Sprintf("%s… (%d chars)", s[:keep], len(s))
}
