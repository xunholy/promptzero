package tools

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/risk"
)

// signalLibraryDefaultRoot returns the default Freqman library root,
// `~/.promptzero/freqman/`. Returns "" when no home directory is
// available (rare; happens in some CI / container shapes); the caller
// degrades to "no library configured".
func signalLibraryDefaultRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".promptzero", "freqman")
}

func init() {
	Register(Spec{
		Name: "signal_library_search",
		Description: "Search Freqman-format Sub-GHz signal libraries on the host filesystem (default: ~/.promptzero/freqman/) for entries matching a frequency or description substring. Read-only; useful before a transmit operation to reuse a vetted catalogue entry instead of capturing fresh.\n\nExamples:\n" +
			`- {"query":"433920000"}  — find every catalogued entry on 433.92 MHz` + "\n" +
			`- {"query":"garage"}  — substring-match descriptions for "garage"` + "\n" +
			`- {"query":"317000000","limit":5}  — capped sweep, hits range entries that cover 317 MHz`,
		Schema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"query":{"type":"string","description":"Frequency in Hz (numeric query) or substring of the description (text query). Case-insensitive."},
				"limit":{"type":"integer","description":"Cap on returned matches (default 50, max 500)."}
			}
		}`),
		Required:  []string{"query"},
		Risk:      risk.Low,
		Group:     GroupMetaUtil,
		AgentOnly: false,
		Handler: func(_ context.Context, _ *Deps, p map[string]any) (string, error) {
			query := str(p, "query")
			if query == "" {
				return "", fmt.Errorf("query required")
			}
			limit := intOr(p, "limit", 50)
			if limit <= 0 {
				limit = 50
			}
			if limit > 500 {
				limit = 500
			}

			root := signalLibraryDefaultRoot()
			if root == "" {
				return "", fmt.Errorf("no Freqman library root available (UserHomeDir failed)")
			}

			matches, errs := fileformat.SearchFreqmanDir(root, query, limit)

			// errs are diagnostics only — don't fail the whole call when one
			// stray non-Freqman .txt happens to live in the library dir.
			errStrs := make([]string, 0, len(errs))
			for _, e := range errs {
				errStrs = append(errStrs, e.Error())
			}

			envelope := map[string]any{
				"root":           root,
				"query":          query,
				"matches":        matches,
				"match_count":    len(matches),
				"limit":          limit,
				"parse_warnings": errStrs,
			}
			b, err := json.MarshalIndent(envelope, "", "  ")
			if err != nil {
				return "", err
			}
			return string(b), nil
		},
	})

	Register(Spec{
		Name: "signal_import",
		Description: "Import a Freqman-format Sub-GHz signal library from a vetted public host into ~/.promptzero/freqman/. Validates the response (size cap, parse, host allowlist) and returns the SHA-256 of the bytes saved so the operator can pin the hash on next-call. Use this to seed the local catalogue from community-curated lists (e.g. lab.flipper.net or a github.com raw URL).\n\n" +
			"Examples:\n" +
			`- {"url":"https://raw.githubusercontent.com/example/signals/main/garages.txt","filename":"garages.txt"}` + "\n" +
			`- {"url":"https://lab.flipper.net/signals/region-eu.txt","expected_sha256":"<hex>","filename":"region-eu.txt"}`,
		Schema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"url":{"type":"string","description":"HTTPS URL of the Freqman list. Hostname must be on the allowlist (lab.flipper.net, flipc.org, raw.githubusercontent.com, gist.githubusercontent.com)."},
				"filename":{"type":"string","description":"Filename to save under ~/.promptzero/freqman/. Must end with .txt; basename only — no directory components. Defaults to the URL basename."},
				"expected_sha256":{"type":"string","description":"Optional 64-character lowercase hex SHA-256. When set, the import is rejected if the actual digest of the response body differs."}
			}
		}`),
		Required:  []string{"url"},
		Risk:      risk.Medium,
		Group:     GroupMetaUtil,
		AgentOnly: false,
		Handler: func(ctx context.Context, _ *Deps, p map[string]any) (string, error) {
			rawURL := str(p, "url")
			if rawURL == "" {
				return "", fmt.Errorf("url required")
			}
			expected := strings.ToLower(strings.TrimSpace(str(p, "expected_sha256")))
			filename := strings.TrimSpace(str(p, "filename"))

			parsed, err := url.Parse(rawURL)
			if err != nil {
				return "", fmt.Errorf("url: %w", err)
			}
			if parsed.Scheme != "https" {
				return "", fmt.Errorf("url: scheme must be https (got %q)", parsed.Scheme)
			}
			if !signalImportHostAllowed(parsed.Hostname()) {
				return "", fmt.Errorf("url: host %q not on allowlist (allowed: %s)",
					parsed.Hostname(), strings.Join(signalImportAllowedHosts, ", "))
			}

			if filename == "" {
				filename = filepath.Base(parsed.Path)
			}
			filename, ferr := signalImportSanitizeFilename(filename)
			if ferr != nil {
				return "", fmt.Errorf("filename: %w", ferr)
			}

			if expected != "" {
				if len(expected) != 64 {
					return "", fmt.Errorf("expected_sha256: must be 64 lowercase hex chars (got %d)", len(expected))
				}
				if _, err := hex.DecodeString(expected); err != nil {
					return "", fmt.Errorf("expected_sha256: not hex: %w", err)
				}
			}

			root := signalLibraryDefaultRoot()
			if root == "" {
				return "", fmt.Errorf("no Freqman library root available (UserHomeDir failed)")
			}

			body, sum, err := signalImportFetch(ctx, rawURL)
			if err != nil {
				return "", err
			}

			if expected != "" && sum != expected {
				return "", fmt.Errorf("sha256 mismatch: got %s, want %s", sum, expected)
			}

			// Validate as Freqman before persisting. Garbage in the cache
			// dir is worse than a failed import — operators key off this
			// directory for catalogue lookups.
			list, err := fileformat.ParseFreqman(body)
			if err != nil {
				return "", fmt.Errorf("downloaded bytes are not a valid Freqman list: %w", err)
			}

			if err := os.MkdirAll(root, 0o755); err != nil {
				return "", fmt.Errorf("mkdir %s: %w", root, err)
			}
			target := filepath.Join(root, filename)
			if err := os.WriteFile(target, body, 0o644); err != nil {
				return "", fmt.Errorf("write %s: %w", target, err)
			}

			envelope := map[string]any{
				"url":             rawURL,
				"saved_to":        target,
				"sha256":          sum,
				"bytes":           len(body),
				"entry_count":     len(list.Entries),
				"verified_pinned": expected != "",
			}
			out, err := json.MarshalIndent(envelope, "", "  ")
			if err != nil {
				return "", err
			}
			return string(out), nil
		},
	})
}

// signalImportAllowedHosts is the small set of vetted public origins from
// which a Freqman list can be fetched. Adding to this list is a deliberate
// PR-time decision: the listed hosts are community-trusted catalogues
// (PortaPack-Mayhem's Flipper lab, the flipc.org index) plus the two
// GitHub raw-content hosts so an operator can pull a community gist or
// repo file. Other hosts are refused even with `expected_sha256` set —
// hash-pinning is a defence-in-depth check, not the primary trust gate.
var signalImportAllowedHosts = []string{
	"lab.flipper.net",
	"flipc.org",
	"raw.githubusercontent.com",
	"gist.githubusercontent.com",
}

func signalImportHostAllowed(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, h := range signalImportAllowedHosts {
		if host == h {
			return true
		}
	}
	return false
}

// signalImportMaxBytes caps a single import. Real-world Freqman lists are
// kilobytes; 1 MiB is well above the largest community-curated catalogue
// observed in the wild and below the size where a malicious response
// would cost meaningful disk or memory.
const signalImportMaxBytes = 1 << 20

// signalImportFetchTimeout is the wall-clock cap for the entire fetch.
// Independent of the broader agent ctx so a stuck handler can still be
// cancelled via the parent ctx but a healthy handler doesn't hang
// forever on a slow CDN.
const signalImportFetchTimeout = 30 * time.Second

// signalImportFetch performs the HTTP GET, enforces the size cap, and
// returns the body bytes + their hex-encoded SHA-256. Redirects are
// allowed but only when the destination host is also on the allowlist —
// a public catalogue often serves through a CDN that 301s elsewhere.
//
// signalImportClient is a package-level var so tests can patch it to
// point at a httptest server without touching the real internet. The
// CheckRedirect hook enforces the allowlist on every redirect hop:
// a public catalogue often serves through a CDN that 301s elsewhere,
// and we refuse if it lands somewhere off-allowlist.
var signalImportClient = &http.Client{
	Timeout: signalImportFetchTimeout,
	CheckRedirect: func(req *http.Request, _ []*http.Request) error {
		if !signalImportHostAllowed(req.URL.Hostname()) {
			return fmt.Errorf("redirected to disallowed host %q", req.URL.Hostname())
		}
		return nil
	},
}

func signalImportFetch(ctx context.Context, rawURL string) ([]byte, string, error) {
	ctx, cancel := context.WithTimeout(ctx, signalImportFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "PromptZero/signal_import")
	req.Header.Set("Accept", "text/plain, */*")

	resp, err := signalImportClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, "", fmt.Errorf("fetch: HTTP %d %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, signalImportMaxBytes+1))
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return nil, "", fmt.Errorf("fetch timed out reading body")
		}
		return nil, "", fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > signalImportMaxBytes {
		return nil, "", fmt.Errorf("fetch: body exceeds %d byte cap", signalImportMaxBytes)
	}

	sum := sha256.Sum256(body)
	return body, hex.EncodeToString(sum[:]), nil
}

// signalImportSanitizeFilename rejects path-traversal attempts and
// enforces the .txt extension. The Freqman parser keys off `*.txt` files
// in SearchFreqmanDir, so a non-.txt name would silently never be picked
// up — better to fail loudly here.
func signalImportSanitizeFilename(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("empty")
	}
	if strings.ContainsAny(name, `/\`) {
		return "", fmt.Errorf("must be a basename — no directory components")
	}
	if name == "." || name == ".." {
		return "", fmt.Errorf("invalid name %q", name)
	}
	if !strings.HasSuffix(strings.ToLower(name), ".txt") {
		return "", fmt.Errorf("must end with .txt")
	}
	return name, nil
}
