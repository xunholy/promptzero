package config

import (
	"fmt"
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
