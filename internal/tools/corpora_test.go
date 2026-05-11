package tools

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helpers

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil { //nolint:gosec
		t.Fatalf("WriteFile: %v", err)
	}
}

func unmarshalResult(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("unmarshal result: %v\nbody=%s", err, body)
	}
	return m
}

// --- ir_irdb_lookup ---------------------------------------------------------

func TestIRIRDBLookup(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "Sony", "BRAVIA_KDL55W800B.ir"), "Filetype: IR signals file\nName: power\n")
	mustWrite(t, filepath.Join(dir, "Sony", "Other.ir"), "Filetype: IR signals file\n")
	mustWrite(t, filepath.Join(dir, "Samsung", "QN90A.ir"), "Filetype: IR signals file\n")
	mustWrite(t, filepath.Join(dir, "Sony", "README.md"), "ignored")

	body, err := irIRDBLookupHandler(context.Background(), nil, map[string]any{
		"manufacturer": "sony",
		"dir":          dir,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	res := unmarshalResult(t, body)
	if got := int(res["hit_count"].(float64)); got != 2 {
		t.Errorf("hit_count = %d, want 2 (two .ir files under Sony)", got)
	}

	body, err = irIRDBLookupHandler(context.Background(), nil, map[string]any{
		"manufacturer": "Sony",
		"device":       "bravia",
		"dir":          dir,
	})
	if err != nil {
		t.Fatalf("handler with device: %v", err)
	}
	res = unmarshalResult(t, body)
	if got := int(res["hit_count"].(float64)); got != 1 {
		t.Errorf("device-filtered hit_count = %d, want 1", got)
	}
}

func TestIRIRDBLookupMissingDir(t *testing.T) {
	t.Setenv("PZ_IRDB_DIR", "")
	_, err := irIRDBLookupHandler(context.Background(), nil, map[string]any{"manufacturer": "x"})
	if err == nil {
		t.Fatalf("expected error for missing dir + missing env")
	}
	if !strings.Contains(err.Error(), "PZ_IRDB_DIR") {
		t.Errorf("err = %v, want PZ_IRDB_DIR mentioned", err)
	}
}

// --- evil_portal_template_pick ----------------------------------------------

func TestEvilPortalTemplatePick(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "Starbucks", "en", "login.html"), "<!DOCTYPE html>\n")
	mustWrite(t, filepath.Join(dir, "Starbucks", "fr", "login.html"), "<!DOCTYPE html>\n")
	mustWrite(t, filepath.Join(dir, "Marriott", "login_en.html"), "<!DOCTYPE html>\n")
	mustWrite(t, filepath.Join(dir, "Starbucks", "logo.png"), "binary")
	mustWrite(t, filepath.Join(dir, "README.md"), "ignored")

	body, err := evilPortalTemplatePickHandler(context.Background(), nil, map[string]any{
		"brand": "starbucks",
		"dir":   dir,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	res := unmarshalResult(t, body)
	if got := int(res["hit_count"].(float64)); got != 2 {
		t.Errorf("hit_count = %d, want 2 (two HTML under Starbucks)", got)
	}

	body, err = evilPortalTemplatePickHandler(context.Background(), nil, map[string]any{
		"brand":    "starbucks",
		"language": "fr",
		"dir":      dir,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	res = unmarshalResult(t, body)
	if got := int(res["hit_count"].(float64)); got != 1 {
		t.Errorf("language-filtered hit_count = %d, want 1", got)
	}
}

func TestEvilPortalLanguageGuess(t *testing.T) {
	cases := map[string]string{
		"en":            "en",
		"fr_FR":         "fr_fr",
		"login_de.html": "de",
		"":              "",
		"foo":           "",
	}
	for in, want := range cases {
		got := guessLanguage(strings.Split(in, string(filepath.Separator)))
		if got != want {
			t.Errorf("guessLanguage(%q) = %q, want %q", in, got, want)
		}
	}
}

// --- badusb_payload_search --------------------------------------------------

func TestBadUSBPayloadSearch(t *testing.T) {
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "windows", "recon.txt"),
		"REM Windows recon\nGUI r\nSTRING powershell -enc ...\n")
	mustWrite(t, filepath.Join(dir, "macos", "exfil.txt"),
		"REM macOS exfiltration\nDELAY 1000\nSTRING curl http://...\n")
	mustWrite(t, filepath.Join(dir, "linux", "irrelevant.txt"),
		"REM Linux fork bomb (do not run)\n")
	mustWrite(t, filepath.Join(dir, "README.md"), "ignored")

	body, err := badusbPayloadSearchHandler(context.Background(), nil, map[string]any{
		"goal": "windows recon",
		"dir":  dir,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	res := unmarshalResult(t, body)
	if got := int(res["hit_count"].(float64)); got < 1 {
		t.Errorf("hit_count = %d, want >=1", got)
	}
	hits := res["hits"].([]any)
	first := hits[0].(map[string]any)
	if !strings.Contains(first["path"].(string), "windows") {
		t.Errorf("top hit not from windows/: %v", first["path"])
	}

	// Filter by target_os.
	body, err = badusbPayloadSearchHandler(context.Background(), nil, map[string]any{
		"goal":      "exfil",
		"target_os": "macos",
		"dir":       dir,
	})
	if err != nil {
		t.Fatalf("handler with target_os: %v", err)
	}
	res = unmarshalResult(t, body)
	if got := int(res["hit_count"].(float64)); got != 1 {
		t.Errorf("target_os-filtered hit_count = %d, want 1", got)
	}
}

// TestCorporaTools_EmptyHitsIsJSONArray pins the v0.167 contract:
// when none of the three corpora-search Specs (ir_irdb_lookup,
// evil_portal_template_pick, badusb_payload_search) finds matches,
// the envelope's `hits` field must be the JSON array `[]`, not
// the literal `null` that `json.Marshal` of a nil slice produces.
// Same defect class as v0.163-v0.166 applied here.
func TestCorporaTools_EmptyHitsIsJSONArray(t *testing.T) {
	emptyDir := t.TempDir() // empty — no .ir / .html / .txt files

	cases := []struct {
		name string
		args map[string]any
	}{
		{"ir_irdb_lookup", map[string]any{"dir": emptyDir, "manufacturer": "Sony"}},
		{"evil_portal_template_pick", map[string]any{"dir": emptyDir, "brand": "google"}},
		{"badusb_payload_search", map[string]any{"dir": emptyDir, "goal": "uac-bypass"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := Get(tc.name)
			if !ok {
				t.Fatalf("%s not registered", tc.name)
			}
			out, err := spec.Handler(context.Background(), &Deps{}, tc.args)
			if err != nil {
				t.Fatalf("Handler: %v", err)
			}
			var parsed map[string]any
			if jerr := json.Unmarshal([]byte(out), &parsed); jerr != nil {
				t.Fatalf("output not parseable JSON: %v\nbody: %s", jerr, out)
			}
			m, hasHits := parsed["hits"]
			if !hasHits {
				t.Fatalf("hits field absent; body: %s", out)
			}
			if m == nil {
				t.Errorf("hits = nil (JSON null); want []. body: %s", out)
			}
			arr, isSlice := m.([]any)
			if !isSlice {
				t.Errorf("hits is not a slice (got %T); body: %s", m, out)
			}
			if arr == nil {
				t.Errorf("hits is a nil-slice (JSON null shape); body: %s", out)
			}
		})
	}
}

// TestClampCorpusLimit pins the cap helper used by all three
// corpora-search Specs. Without the cap an LLM tool call asking
// for limit=1000000 would walk the entire corpus and serialise a
// multi-MB JSON into the tool-result block.
func TestClampCorpusLimit(t *testing.T) {
	cases := []struct {
		in, want int
	}{
		{0, 0},
		{50, 50},
		{1000, 1000},   // exactly cap
		{1001, 1000},   // one above
		{999999, 1000}, // typical adversarial value
		{-5, -5},       // negative passes through; callers handle
	}
	for _, c := range cases {
		got := clampCorpusLimit(c.in)
		if got != c.want {
			t.Errorf("clampCorpusLimit(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}
