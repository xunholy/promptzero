package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRedactKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "redacted"},
		{"short", "redacted"},
		{"1234567", "redacted"}, // exactly 7 chars — below threshold
		{"12345678", "...5678"}, // exactly 8 chars — show last 4
		{"sk-ant-api-ABCD", "...ABCD"},
		{"sk-ant-api03-verylongkey1234", "...1234"},
	}
	for _, tc := range tests {
		got := redactKey(tc.input)
		if got != tc.want {
			t.Errorf("redactKey(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestConfig_StringRedactsKeys(t *testing.T) {
	cfg := &Config{
		APIKey:    "sk-ant-api03-supersecretkey1234",
		OpenAIKey: "sk-openai-supersecretkey5678",
		Model:     "claude-opus-4-7",
	}

	// %v must not contain the full keys
	v := fmt.Sprintf("%v", cfg)
	if strings.Contains(v, "supersecretkey1234") {
		t.Errorf("%%v leaked APIKey: %s", v)
	}
	if strings.Contains(v, "supersecretkey5678") {
		t.Errorf("%%v leaked OpenAIKey: %s", v)
	}
	// must contain the masked tail
	if !strings.Contains(v, "1234") {
		t.Errorf("%%v missing masked tail of APIKey: %s", v)
	}

	// %+v must not contain the full keys
	pv := fmt.Sprintf("%+v", cfg)
	if strings.Contains(pv, "supersecretkey1234") {
		t.Errorf("%%+v leaked APIKey: %s", pv)
	}
	if strings.Contains(pv, "supersecretkey5678") {
		t.Errorf("%%+v leaked OpenAIKey: %s", pv)
	}

	// %#v must not contain the full keys
	gv := fmt.Sprintf("%#v", cfg)
	if strings.Contains(gv, "supersecretkey1234") {
		t.Errorf("%%#v leaked APIKey: %s", gv)
	}
	if strings.Contains(gv, "supersecretkey5678") {
		t.Errorf("%%#v leaked OpenAIKey: %s", gv)
	}
}

func TestConfig_StringShortKeyRedacted(t *testing.T) {
	cfg := Config{
		APIKey:    "short",
		OpenAIKey: "tiny",
	}
	v := fmt.Sprintf("%v", cfg)
	if !strings.Contains(v, "redacted") {
		t.Errorf("expected 'redacted' for short key in %%v: %s", v)
	}
	// Must not leak the short key verbatim
	if strings.Contains(v, "short") {
		t.Errorf("%%v leaked short APIKey: %s", v)
	}
}

func TestLoad_DefaultsWhenFileMissing(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("PROMPTZERO_WEB_TOKEN", "")
	cfg, err := Load(filepath.Join(dir, "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Model != "claude-opus-4-8" {
		t.Errorf("default Model = %q, want claude-opus-4-8", cfg.Model)
	}
	if cfg.Serial.Port != "/dev/ttyACM0" {
		t.Errorf("default Serial.Port = %q", cfg.Serial.Port)
	}
	if cfg.Serial.BaudRate != 230400 {
		t.Errorf("default Serial.BaudRate = %d, want 230400", cfg.Serial.BaudRate)
	}
	if cfg.Marauder.BaudRate != 115200 {
		t.Errorf("default Marauder.BaudRate = %d, want 115200", cfg.Marauder.BaudRate)
	}
	if cfg.Web.Port != 8080 {
		t.Errorf("default Web.Port = %d, want 8080", cfg.Web.Port)
	}
	if cfg.Observability.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want info", cfg.Observability.LogLevel)
	}
	if !cfg.Observability.MetricsEnabled {
		t.Error("MetricsEnabled should default to true")
	}
}

func TestLoad_ParsesYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := `
model: claude-sonnet-4-6
serial:
  port: /dev/ttyUSB0
  baud_rate: 921600
web:
  port: 9999
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Model != "claude-sonnet-4-6" {
		t.Errorf("Model = %q, want claude-sonnet-4-6", cfg.Model)
	}
	if cfg.Serial.Port != "/dev/ttyUSB0" {
		t.Errorf("Serial.Port = %q", cfg.Serial.Port)
	}
	if cfg.Serial.BaudRate != 921600 {
		t.Errorf("Serial.BaudRate = %d", cfg.Serial.BaudRate)
	}
	if cfg.Web.Port != 9999 {
		t.Errorf("Web.Port = %d", cfg.Web.Port)
	}
	// Marauder defaults survive when not in YAML.
	if cfg.Marauder.BaudRate != 115200 {
		t.Errorf("Marauder.BaudRate = %d, want default 115200", cfg.Marauder.BaudRate)
	}
}

func TestLoad_RejectsMalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(path, []byte("model: [unclosed"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if !strings.Contains(err.Error(), "parsing config") {
		t.Errorf("error %q should mention 'parsing config'", err.Error())
	}
}

func TestLoad_FallsBackToHomeDir(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pzDir := filepath.Join(home, ".promptzero")
	if err := os.MkdirAll(pzDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pzDir, "config.yaml"),
		[]byte("model: claude-haiku-4-5\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	cfg, err := Load(filepath.Join(t.TempDir(), "missing.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Model != "claude-haiku-4-5" {
		t.Errorf("expected fallback to ~/.promptzero/config.yaml, got Model=%q", cfg.Model)
	}
}

// TestLoad_ParseErrorReferencesFallbackPath pins that when the
// requested config is absent and the ~/.promptzero/config.yaml
// fallback exists but has malformed YAML, the parse error names the
// fallback path (the file actually read) — not the requested path
// (which was never read). Pre-v0.140 the error attributed the failure
// to the missing requested path, sending the operator to edit a file
// that didn't exist.
func TestLoad_ParseErrorReferencesFallbackPath(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	pzDir := filepath.Join(home, ".promptzero")
	if err := os.MkdirAll(pzDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fallback := filepath.Join(pzDir, "config.yaml")
	if err := os.WriteFile(fallback, []byte("model: [unclosed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ANTHROPIC_API_KEY", "")
	requested := filepath.Join(t.TempDir(), "missing.yaml")
	_, err := Load(requested)
	if err == nil {
		t.Fatal("expected error for malformed fallback YAML")
	}
	if strings.Contains(err.Error(), requested) {
		t.Errorf("error references requested path %q; it should reference the fallback %q\nerr=%v",
			requested, fallback, err)
	}
	if !strings.Contains(err.Error(), fallback) {
		t.Errorf("error should reference fallback path %q\nerr=%v", fallback, err)
	}
}

func TestLoad_EnvVarsOverrideConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	body := "api_key: from-config\nopenai_key: from-config-openai\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", dir)
	t.Setenv("ANTHROPIC_API_KEY", "from-env-anthropic")
	t.Setenv("OPENAI_API_KEY", "from-env-openai")
	t.Setenv("PROMPTZERO_WEB_TOKEN", "from-env-token")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.APIKey != "from-env-anthropic" {
		t.Errorf("ANTHROPIC_API_KEY did not override config: %q", cfg.APIKey)
	}
	if cfg.OpenAIKey != "from-env-openai" {
		t.Errorf("OPENAI_API_KEY did not override config: %q", cfg.OpenAIKey)
	}
	if cfg.Web.Token != "from-env-token" {
		t.Errorf("PROMPTZERO_WEB_TOKEN did not override: %q", cfg.Web.Token)
	}
}

func TestLoadWebHostPortEnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	t.Setenv("PROMPTZERO_WEB_HOST", "0.0.0.0")
	t.Setenv("PROMPTZERO_WEB_PORT", "9090")
	cfg, err := Load(filepath.Join(dir, "nonexistent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Web.Host != "0.0.0.0" {
		t.Errorf("PROMPTZERO_WEB_HOST did not override: %q", cfg.Web.Host)
	}
	if cfg.Web.Port != 9090 {
		t.Errorf("PROMPTZERO_WEB_PORT did not override: %d", cfg.Web.Port)
	}

	// An invalid or out-of-range port is ignored, leaving the default intact.
	for _, bad := range []string{"not-a-number", "0", "70000", "-1"} {
		t.Setenv("PROMPTZERO_WEB_PORT", bad)
		cfg, err := Load(filepath.Join(dir, "nonexistent.yaml"))
		if err != nil {
			t.Fatalf("Load(%q): %v", bad, err)
		}
		if cfg.Web.Port != 8080 {
			t.Errorf("PROMPTZERO_WEB_PORT=%q should be ignored, got port %d", bad, cfg.Web.Port)
		}
	}
}

func TestRequireAPIKey(t *testing.T) {
	cfg := &Config{}
	if err := cfg.RequireAPIKey(); err == nil {
		t.Error("RequireAPIKey should error when APIKey is empty")
	}
	cfg.APIKey = "sk-ant-something"
	if err := cfg.RequireAPIKey(); err != nil {
		t.Errorf("RequireAPIKey should pass with key set: %v", err)
	}
}
