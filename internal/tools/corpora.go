// corpora.go — search Specs for operator-curated asset directories.
//
// PromptZero deliberately does NOT bundle third-party Sub-GHz / IR /
// BadUSB / evil-portal corpora — license review is each operator's
// responsibility, and the upstream repos churn fast enough that a
// vendored snapshot would go stale within months. Instead, these Specs
// accept a path to a directory the operator has cloned/curated (e.g.
// `~/share/Flipper-IRDB/`, `~/share/badusb-payloads/`) and search it.
//
// Three Specs land here:
//
//   - ir_irdb_lookup            — search a Flipper-IRDB-shaped tree by
//                                  manufacturer + device.
//   - evil_portal_template_pick — list HTML/JS templates under a
//                                  directory (e.g. flipper-zero-evil-portal,
//                                  L-ubu/flipper-portals).
//   - badusb_payload_search     — grep Ducky-script .txt files for a
//                                  goal keyword and return ranked hits.
//
// Defaults for each tool's directory come from environment variables so
// agents can omit the path argument once the operator has set them once:
//
//   PZ_IRDB_DIR              — default for ir_irdb_lookup
//   PZ_EVIL_PORTAL_DIR       — default for evil_portal_template_pick
//   PZ_BADUSB_DIR            — default for badusb_payload_search

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

// corpusMaxResults caps how many hits any corpora-search Spec
// (ir_irdb_lookup, evil_portal_template_pick, badusb_payload_search)
// will return per call. Without the cap an LLM tool call with
// limit=1000000 would walk the entire corpus and serialise a
// multi-MB JSON into the tool-result block — eating context budget
// and potentially OOM'ing the agent on large operator trees.
// 1000 is generous for any reasonable triage flow.
const corpusMaxResults = 1000

// clampCorpusLimit applies the corpora-search row cap. Centralised
// so the three corpora tools stay consistent and the constant has a
// single source of truth.
func clampCorpusLimit(n int) int {
	if n > corpusMaxResults {
		return corpusMaxResults
	}
	return n
}

func init() { //nolint:gochecknoinits
	Register(irIRDBLookupSpec)
	Register(evilPortalTemplatePickSpec)
	Register(badusbPayloadSearchSpec)
}

// --- ir_irdb_lookup ---------------------------------------------------------

var irIRDBLookupSpec = Spec{
	Name:        "ir_irdb_lookup",
	Description: "Search an operator-supplied IRDB tree (Lucaslhm/Flipper-IRDB layout: <root>/<Manufacturer>/<Device>.ir). Returns a ranked list of matching .ir paths and their first-line metadata. The path comes from the dir argument, falls back to the PZ_IRDB_DIR env var. No I/O beyond the directory walk; safe to call freely.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"manufacturer":{"type":"string","description":"Manufacturer substring to match (case-insensitive)"},
			"device":{"type":"string","description":"Device substring to match (case-insensitive). Optional."},
			"dir":{"type":"string","description":"IRDB root directory. Optional; defaults to PZ_IRDB_DIR env."},
			"limit":{"type":"integer","description":"Max results to return. Default 50."}
		},
		"required":["manufacturer"]
	}`),
	Required:  []string{"manufacturer"},
	Risk:      risk.Low,
	Group:     GroupFlipperIR,
	AgentOnly: false,
	Handler:   irIRDBLookupHandler,
}

func irIRDBLookupHandler(_ context.Context, _ *Deps, args map[string]any) (string, error) {
	root := str(args, "dir")
	if root == "" {
		root = os.Getenv("PZ_IRDB_DIR")
	}
	if root == "" {
		return "", fmt.Errorf("ir_irdb_lookup: dir is empty and PZ_IRDB_DIR not set")
	}
	mfg := strings.ToLower(strings.TrimSpace(str(args, "manufacturer")))
	if mfg == "" {
		return "", fmt.Errorf("ir_irdb_lookup: manufacturer is required")
	}
	device := strings.ToLower(strings.TrimSpace(str(args, "device")))
	limit := clampCorpusLimit(intOr(args, "limit", 50))

	type hit struct {
		Path         string `json:"path"`
		Manufacturer string `json:"manufacturer"`
		Device       string `json:"device"`
		Header       string `json:"header,omitempty"`
	}
	// Non-nil empty slice so the envelope's `"hits"` field serialises
	// as `[]` rather than the JSON null literal when no .ir files
	// match. Same v0.163-v0.166 contract.
	hits := []hit{}

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // tolerate broken symlinks etc.
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(p), ".ir") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		parts := strings.SplitN(rel, string(filepath.Separator), 3)
		if len(parts) < 1 {
			return nil
		}
		mfgPart := strings.ToLower(parts[0])
		devicePart := ""
		if len(parts) > 1 {
			devicePart = strings.ToLower(strings.TrimSuffix(parts[len(parts)-1], ".ir"))
		}
		if !strings.Contains(mfgPart, mfg) {
			return nil
		}
		if device != "" && !strings.Contains(devicePart, device) {
			return nil
		}
		header := readFirstLine(p)
		hits = append(hits, hit{
			Path:         p,
			Manufacturer: parts[0],
			Device:       strings.TrimSuffix(parts[len(parts)-1], ".ir"),
			Header:       header,
		})
		if len(hits) >= limit {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("ir_irdb_lookup: walk %s: %w", root, err)
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Manufacturer != hits[j].Manufacturer {
			return hits[i].Manufacturer < hits[j].Manufacturer
		}
		return hits[i].Device < hits[j].Device
	})

	body, _ := json.Marshal(map[string]any{
		"root":         root,
		"manufacturer": str(args, "manufacturer"),
		"device":       str(args, "device"),
		"hit_count":    len(hits),
		"hits":         hits,
	})
	return string(body), nil
}

// --- evil_portal_template_pick ----------------------------------------------

var evilPortalTemplatePickSpec = Spec{
	Name:        "evil_portal_template_pick",
	Description: "List HTML/JS evil-portal templates under an operator-supplied directory and return matches by brand/language. Useful before generate_evil_portal so the agent can pick a known-good template instead of synthesizing one. Path from dir arg or PZ_EVIL_PORTAL_DIR env. Read-only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"brand":{"type":"string","description":"Brand/network substring to match (case-insensitive). Examples: starbucks, marriott, gogoinflight."},
			"language":{"type":"string","description":"ISO 639-1 lang code substring to match (en, fr, ja, ...). Optional."},
			"dir":{"type":"string","description":"Templates directory. Optional; defaults to PZ_EVIL_PORTAL_DIR env."},
			"limit":{"type":"integer","description":"Max results. Default 30."}
		}
	}`),
	Required:  nil,
	Risk:      risk.Low,
	Group:     GroupGen,
	AgentOnly: false,
	Handler:   evilPortalTemplatePickHandler,
}

func evilPortalTemplatePickHandler(_ context.Context, _ *Deps, args map[string]any) (string, error) {
	root := str(args, "dir")
	if root == "" {
		root = os.Getenv("PZ_EVIL_PORTAL_DIR")
	}
	if root == "" {
		return "", fmt.Errorf("evil_portal_template_pick: dir is empty and PZ_EVIL_PORTAL_DIR not set")
	}
	brand := strings.ToLower(strings.TrimSpace(str(args, "brand")))
	lang := strings.ToLower(strings.TrimSpace(str(args, "language")))
	limit := clampCorpusLimit(intOr(args, "limit", 30))

	type hit struct {
		Path     string `json:"path"`
		Brand    string `json:"brand"`
		Language string `json:"language,omitempty"`
		Sample   string `json:"sample,omitempty"`
	}
	// Non-nil empty slice so the envelope's `"hits"` field serialises
	// as `[]` rather than null when no portal templates match. Same
	// v0.163-v0.166 contract.
	hits := []hit{}

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		lp := strings.ToLower(p)
		if !strings.HasSuffix(lp, ".html") && !strings.HasSuffix(lp, ".htm") &&
			!strings.HasSuffix(lp, ".js") && !strings.HasSuffix(lp, ".css") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		parts := strings.Split(rel, string(filepath.Separator))
		if len(parts) == 0 {
			return nil
		}
		brandPart := parts[0]
		if brand != "" && !strings.Contains(strings.ToLower(brandPart), brand) {
			return nil
		}

		langGuess := guessLanguage(parts)
		if lang != "" && !strings.Contains(strings.ToLower(langGuess), lang) {
			return nil
		}

		hits = append(hits, hit{
			Path:     p,
			Brand:    brandPart,
			Language: langGuess,
			Sample:   readFirstLine(p),
		})
		if len(hits) >= limit {
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("evil_portal_template_pick: walk %s: %w", root, err)
	}

	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Brand != hits[j].Brand {
			return hits[i].Brand < hits[j].Brand
		}
		return hits[i].Path < hits[j].Path
	})

	body, _ := json.Marshal(map[string]any{
		"root":      root,
		"brand":     str(args, "brand"),
		"language":  str(args, "language"),
		"hit_count": len(hits),
		"hits":      hits,
	})
	return string(body), nil
}

// guessLanguage extracts a 2-3 char language hint from a path, scanning
// common conventions: a dedicated language directory ("en/", "fr_FR/"),
// or a suffix on the filename ("login_en.html"). Returns empty when no
// hint is detectable.
func guessLanguage(parts []string) string {
	for _, p := range parts {
		lp := strings.ToLower(p)
		if isLangCode(lp) {
			return lp
		}
		if i := strings.LastIndexByte(lp, '_'); i >= 0 {
			suffix := strings.TrimSuffix(lp[i+1:], filepath.Ext(lp))
			if isLangCode(suffix) {
				return suffix
			}
		}
	}
	return ""
}

func isLangCode(s string) bool {
	if len(s) == 2 || len(s) == 5 {
		for _, r := range s {
			if (r < 'a' || r > 'z') && r != '_' {
				return false
			}
		}
		return true
	}
	return false
}

// --- badusb_payload_search --------------------------------------------------

var badusbPayloadSearchSpec = Spec{
	Name:        "badusb_payload_search",
	Description: "Search an operator-supplied BadUSB payload corpus (Ducky-script .txt files) for files matching a goal keyword. Returns ranked hits with the first ~6 lines of each hit so the agent can pick a template before generate_badusb. Path from dir arg or PZ_BADUSB_DIR env. Read-only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"goal":{"type":"string","description":"Keyword(s) to grep for in payload bodies + filenames. Examples: 'windows recon', 'macos persistence', 'reverse shell'."},
			"target_os":{"type":"string","description":"Optional OS filter: windows | macos | linux | android. Filters by parent directory name."},
			"dir":{"type":"string","description":"Payload corpus root. Optional; defaults to PZ_BADUSB_DIR env."},
			"limit":{"type":"integer","description":"Max results. Default 20."}
		},
		"required":["goal"]
	}`),
	Required:  []string{"goal"},
	Risk:      risk.Low,
	Group:     GroupFlipperBadUSB,
	AgentOnly: false,
	Handler:   badusbPayloadSearchHandler,
}

func badusbPayloadSearchHandler(_ context.Context, _ *Deps, args map[string]any) (string, error) {
	root := str(args, "dir")
	if root == "" {
		root = os.Getenv("PZ_BADUSB_DIR")
	}
	if root == "" {
		return "", fmt.Errorf("badusb_payload_search: dir is empty and PZ_BADUSB_DIR not set")
	}
	goal := strings.ToLower(strings.TrimSpace(str(args, "goal")))
	if goal == "" {
		return "", fmt.Errorf("badusb_payload_search: goal is required")
	}
	keywords := strings.Fields(goal)
	osFilter := strings.ToLower(strings.TrimSpace(str(args, "target_os")))
	limit := clampCorpusLimit(intOr(args, "limit", 20))

	type hit struct {
		Path    string   `json:"path"`
		Score   int      `json:"score"`
		Preview []string `json:"preview"`
	}
	// Non-nil empty slice so the envelope's `"hits"` field serialises
	// as `[]` rather than null when no badusb payloads match. Same
	// v0.163-v0.166 contract.
	hits := []hit{}

	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			return nil
		}
		lp := strings.ToLower(p)
		if !strings.HasSuffix(lp, ".txt") && !strings.HasSuffix(lp, ".duck") && !strings.HasSuffix(lp, ".duckyscript") {
			return nil
		}
		if osFilter != "" && !strings.Contains(lp, osFilter) {
			return nil
		}

		body, err := os.ReadFile(p) //nolint:gosec // operator-curated tree
		if err != nil {
			return nil
		}
		score := 0
		bodyLower := strings.ToLower(string(body))
		for _, kw := range keywords {
			if strings.Contains(bodyLower, kw) {
				score += 5
			}
			if strings.Contains(lp, kw) {
				score += 3 // filename match weighted lower than body match
			}
		}
		if score == 0 {
			return nil
		}

		hits = append(hits, hit{
			Path:    p,
			Score:   score,
			Preview: firstNLines(body, 6),
		})
		return nil
	})
	if err != nil {
		return "", fmt.Errorf("badusb_payload_search: walk %s: %w", root, err)
	}

	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		return hits[i].Path < hits[j].Path
	})
	if len(hits) > limit {
		hits = hits[:limit]
	}

	body, _ := json.Marshal(map[string]any{
		"root":      root,
		"goal":      str(args, "goal"),
		"target_os": str(args, "target_os"),
		"hit_count": len(hits),
		"hits":      hits,
	})
	return string(body), nil
}

// readFirstLine returns the first newline-terminated line of path, or
// the file content if it has no newline. Used for surfacing a quick
// metadata preview without reading the whole file.
func readFirstLine(path string) string {
	b, err := os.ReadFile(path) //nolint:gosec // operator-curated tree
	if err != nil {
		return ""
	}
	if i := strings.IndexByte(string(b), '\n'); i >= 0 {
		return strings.TrimSpace(string(b[:i]))
	}
	return strings.TrimSpace(string(b))
}

// firstNLines splits b on \n and returns up to n leading lines, trimming
// trailing carriage returns.
func firstNLines(b []byte, n int) []string {
	lines := strings.Split(string(b), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, "\r")
	}
	return lines
}
