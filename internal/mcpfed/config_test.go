package mcpfed

import (
	"testing"
	"time"
)

func TestClientConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ClientConfig
		wantErr bool
	}{
		{"empty", ClientConfig{}, true},
		{"prefix invalid char", ClientConfig{Prefix: "Bad", Transport: "stdio", Command: "x"}, true},
		{"prefix starts digit", ClientConfig{Prefix: "1bad", Transport: "stdio", Command: "x"}, true},
		{"unknown transport", ClientConfig{Prefix: "ok", Transport: "udp", Command: "x"}, true},
		{"stdio missing cmd", ClientConfig{Prefix: "ok", Transport: "stdio"}, true},
		{"stdio with url", ClientConfig{Prefix: "ok", Transport: "stdio", Command: "x", URL: "http://x"}, true},
		{"http missing url", ClientConfig{Prefix: "ok", Transport: "http"}, true},
		{"http with cmd", ClientConfig{Prefix: "ok", Transport: "http", URL: "http://x", Command: "y"}, true},
		{"http sandbox docker", ClientConfig{Prefix: "ok", Transport: "http", URL: "http://x", Sandbox: "docker"}, true},
		{"unknown sandbox", ClientConfig{Prefix: "ok", Transport: "stdio", Command: "x", Sandbox: "bogus"}, true},
		{"unknown risk default", ClientConfig{Prefix: "ok", Transport: "stdio", Command: "x", RiskDefault: "bogus"}, true},

		{"valid stdio", ClientConfig{Prefix: "ok", Transport: "stdio", Command: "x"}, false},
		{"valid http", ClientConfig{Prefix: "ok", Transport: "http", URL: "http://x"}, false},
		{"valid sse", ClientConfig{Prefix: "ok", Transport: "sse", URL: "http://x"}, false},
		{"valid all sandboxes", ClientConfig{Prefix: "ok", Transport: "stdio", Command: "x", Sandbox: "docker"}, false},
		{"valid risk default", ClientConfig{Prefix: "ok", Transport: "stdio", Command: "x", RiskDefault: "low"}, false},
		{"valid prefix with hyphen", ClientConfig{Prefix: "abc-def", Transport: "stdio", Command: "x"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr && err == nil {
				t.Fatalf("want error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestClientConfigResolveEnv(t *testing.T) {
	t.Setenv("MCPFED_TEST_API_KEY", "sk-test-1234")

	cfg := ClientConfig{
		Env: map[string]string{
			"PASSTHROUGH": "$MCPFED_TEST_API_KEY",
			"LITERAL":     "abc",
			"MISSING":     "$DOES_NOT_EXIST_xyz",
		},
	}
	got := cfg.resolveEnv()

	want := map[string]string{
		"PASSTHROUGH": "sk-test-1234",
		"LITERAL":     "abc",
		"MISSING":     "",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d (got=%v)", len(got), len(want), got)
	}
	gotMap := map[string]string{}
	for _, kv := range got {
		k, v, ok := splitKV(kv)
		if !ok {
			t.Fatalf("malformed env entry %q", kv)
		}
		gotMap[k] = v
	}
	for k, v := range want {
		if gotMap[k] != v {
			t.Errorf("env[%s] = %q, want %q", k, gotMap[k], v)
		}
	}
}

func splitKV(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return "", "", false
}

func TestClientConfigInitTimeoutDefault(t *testing.T) {
	cfg := ClientConfig{}
	if d := cfg.initTimeout(); d != 30*time.Second {
		t.Errorf("default initTimeout = %v, want 30s", d)
	}

	cfg.InitTimeout = 5 * time.Second
	if d := cfg.initTimeout(); d != 5*time.Second {
		t.Errorf("explicit initTimeout = %v, want 5s", d)
	}
}

func TestClientConfigHealthInterval(t *testing.T) {
	cfg := ClientConfig{}
	d, on := cfg.healthInterval()
	if !on {
		t.Errorf("zero HealthInterval should default to enabled")
	}
	if d != 30*time.Second {
		t.Errorf("default healthInterval = %v, want 30s", d)
	}

	cfg.HealthInterval = 10 * time.Second
	d, on = cfg.healthInterval()
	if !on || d != 10*time.Second {
		t.Errorf("explicit healthInterval = (%v, %v), want (10s, true)", d, on)
	}

	cfg.HealthInterval = -1
	d, on = cfg.healthInterval()
	if on {
		t.Errorf("negative HealthInterval should disable")
	}
	if d != 0 {
		t.Errorf("disabled healthInterval cadence = %v, want 0", d)
	}
}
