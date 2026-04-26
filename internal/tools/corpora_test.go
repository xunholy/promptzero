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
