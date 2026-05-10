package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

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
}
