package tools

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// helpers_test.go covers the pure helpers across firmware_extract.go,
// faultier.go, and canbus.go that were 0%-tested despite shaping
// load-bearing operator-visible output (firmware tree summarisation,
// "interesting files" classifier, output-tail truncation, faultier
// outcome name, CAN bus result envelope).

// TestSummariseTree pins the recursive walk: every regular file
// returned as a path relative to root, sorted ascending, capped
// at maxFiles. Directories are excluded. Walk errors silenced
// (partial output is more useful than nothing).
func TestSummariseTree(t *testing.T) {
	root := t.TempDir()
	// Build a small tree:
	//   root/
	//     a.txt
	//     b.txt
	//     sub/
	//       c.txt
	//       deep/
	//         d.txt
	if err := os.WriteFile(filepath.Join(root, "a.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "b.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "c.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "sub", "deep"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "sub", "deep", "d.txt"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("happy_path", func(t *testing.T) {
		got := summariseTree(root, 100)
		want := []string{
			"a.txt",
			"b.txt",
			filepath.Join("sub", "c.txt"),
			filepath.Join("sub", "deep", "d.txt"),
		}
		if len(got) != len(want) {
			t.Fatalf("got %d files, want %d: %v", len(got), len(want), got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("got[%d] = %q, want %q", i, got[i], want[i])
			}
		}
	})

	t.Run("max_files_cap", func(t *testing.T) {
		got := summariseTree(root, 2)
		if len(got) > 2 {
			t.Errorf("got %d files, want ≤ 2 (cap)", len(got))
		}
	})

	t.Run("nonexistent_root_returns_empty", func(t *testing.T) {
		// Filesystem errors are silenced.
		got := summariseTree("/nonexistent/path/that/does/not/exist", 100)
		if len(got) != 0 {
			t.Errorf("got %d files for nonexistent root, want 0: %v", len(got), got)
		}
	})
}

// TestClassifyInteresting pins the "look-here-first" heuristic.
// Patterns match anywhere in the path (case insensitive); a file
// hits only once even if multiple patterns match. Empty input →
// empty output. The result follows input order (no internal sort).
func TestClassifyInteresting(t *testing.T) {
	tree := []string{
		"root/etc/shadow",
		"root/usr/bin/normal",
		"home/user/.ssh/id_rsa",
		"home/user/.ssh/authorized_keys",
		"opt/SECRET_TOKEN.txt",   // case-insensitive match
		"opt/normal/file.txt",    // no match
		"var/log/messages",       // no match
		"etc/init.d/rcS",         // multi-pattern (rcS + init) — still one hit
		"certs/server.pem",       // .pem
		"certs/server.crt",       // .crt
		"data/config.bin",        // config.bin
		"etc/passwd",             // passwd
		"etc/htpasswd",           // htpasswd
		"backup/old.p12",         // .p12
		"src/hardcoded_creds.go", // hardcode (substring)
	}
	got := classifyInteresting(tree)

	mustContain := []string{
		"root/etc/shadow",
		"home/user/.ssh/id_rsa",
		"home/user/.ssh/authorized_keys",
		"opt/SECRET_TOKEN.txt",
		"etc/init.d/rcS",
		"certs/server.pem",
		"certs/server.crt",
		"data/config.bin",
		"etc/passwd",
		"etc/htpasswd",
		"backup/old.p12",
		"src/hardcoded_creds.go",
	}
	for _, want := range mustContain {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("classifyInteresting missing %q in result: %v", want, got)
		}
	}

	// No double-hits even when multiple patterns match. rcS matches
	// both "rcS" and "init" but should appear exactly once.
	rcSCount := 0
	for _, g := range got {
		if g == "etc/init.d/rcS" {
			rcSCount++
		}
	}
	if rcSCount != 1 {
		t.Errorf("etc/init.d/rcS appeared %d times, want 1 (de-dup via break)", rcSCount)
	}

	// Negative cases — must NOT appear.
	mustNotContain := []string{"root/usr/bin/normal", "opt/normal/file.txt", "var/log/messages"}
	for _, drop := range mustNotContain {
		for _, g := range got {
			if g == drop {
				t.Errorf("classifyInteresting wrongly flagged %q as interesting", drop)
			}
		}
	}

	// Empty input → empty output.
	if got := classifyInteresting(nil); len(got) != 0 {
		t.Errorf("classifyInteresting(nil) returned %v, want []", got)
	}
	if got := classifyInteresting([]string{}); len(got) != 0 {
		t.Errorf("classifyInteresting([]) returned %v, want []", got)
	}
}

// TestSummariseTree_NonNilOnEmpty pins the v0.166 contract: an
// empty directory yields a non-nil empty slice so the
// firmware_extract envelope's `file_tree` field serialises as
// `[]` rather than the JSON null literal. Same arc as v0.163
// (audit.Export), v0.164 (audit_query), v0.165
// (signal_library_search).
func TestSummariseTree_NonNilOnEmpty(t *testing.T) {
	emptyDir := t.TempDir()
	got := summariseTree(emptyDir, 200)
	if got == nil {
		t.Errorf("summariseTree on empty dir returned nil; want non-nil empty slice")
	}
	if len(got) != 0 {
		t.Errorf("expected empty slice, got %v", got)
	}
	// JSON round-trip to confirm it marshals as []. A nil slice
	// would marshal as the literal "null" inside an envelope.
	body, err := json.Marshal(map[string]any{"file_tree": got})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"file_tree":[]`) {
		t.Errorf("envelope should carry file_tree:[]; got %s", body)
	}
}

// TestClassifyInteresting_NonNilOnEmpty pins the same contract for
// classifyInteresting — even when no patterns match, the result
// is `[]`, not `null`.
func TestClassifyInteresting_NonNilOnEmpty(t *testing.T) {
	got := classifyInteresting([]string{"normal/file.txt", "other.go"})
	if got == nil {
		t.Errorf("classifyInteresting with no matches returned nil; want non-nil empty slice")
	}
	body, err := json.Marshal(map[string]any{"interesting": got})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(body), `"interesting":[]`) {
		t.Errorf("envelope should carry interesting:[]; got %s", body)
	}
}

// TestTail pins the byte-truncator used to cap stdout/stderr
// captures the agent feeds into prompt cache. Under-budget input
// passes through verbatim; over-budget input prefixes
// "...[truncated N bytes]...\n" and keeps the LAST n bytes.
func TestTail(t *testing.T) {
	t.Run("under_budget", func(t *testing.T) {
		in := []byte("hello world")
		got := tail(in, 100)
		if got != "hello world" {
			t.Errorf("tail(short, 100) = %q, want verbatim", got)
		}
	})

	t.Run("at_budget", func(t *testing.T) {
		in := []byte("12345")
		got := tail(in, 5)
		if got != "12345" {
			t.Errorf("tail(exact, n=5) = %q, want verbatim (≤ branch)", got)
		}
	})

	t.Run("over_budget_keeps_tail", func(t *testing.T) {
		in := []byte("0123456789abcdef") // 16 bytes
		got := tail(in, 5)
		// Truncation marker + last 5 bytes.
		if !strings.HasPrefix(got, "...[truncated 11 bytes]...\n") {
			t.Errorf("tail missing truncation prefix: %q", got)
		}
		if !strings.HasSuffix(got, "bcdef") {
			t.Errorf("tail = %q, want suffix 'bcdef' (last 5 bytes)", got)
		}
	})

	t.Run("empty_input", func(t *testing.T) {
		if got := tail(nil, 10); got != "" {
			t.Errorf("tail(nil) = %q, want \"\"", got)
		}
		if got := tail([]byte{}, 10); got != "" {
			t.Errorf("tail([]) = %q, want \"\"", got)
		}
	})
}

// TestFaultierOutcomeString pins the byte → label mapping the
// glitch_status tool surfaces to the agent. A regression here
// would silently misreport whether a glitch attempt succeeded
// (mapping 0x04 "ok" → "crash" would be operationally
// terrifying).
func TestFaultierOutcomeString(t *testing.T) {
	cases := []struct {
		in   byte
		want string
	}{
		{0x00, "none"},
		{0x01, "skip"},
		{0x02, "crash"},
		{0x03, "glitch"},
		{0x04, "ok"},
		{0x05, "unknown(0x05)"},
		{0x42, "unknown(0x42)"},
		{0xFF, "unknown(0xFF)"},
	}
	for _, c := range cases {
		if got := faultierOutcomeString(c.in); got != c.want {
			t.Errorf("faultierOutcomeString(0x%02X) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestWrapCANResult pins the JSON envelope wrapper around can-
// utils container output. Nil error → status=ok + raw_output;
// non-nil error → raw_output + error message + propagated err.
func TestWrapCANResult(t *testing.T) {
	t.Run("happy_path", func(t *testing.T) {
		body, err := wrapCANResult("can0  123   [4]  DE AD BE EF\n", nil)
		if err != nil {
			t.Fatalf("wrapCANResult(ok): unexpected err %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("body not JSON: %v\n%s", err, body)
		}
		if m["status"] != "ok" {
			t.Errorf("status = %v, want ok", m["status"])
		}
		if !strings.Contains(m["raw_output"].(string), "DE AD BE EF") {
			t.Errorf("raw_output missing payload: %v", m["raw_output"])
		}
		if _, has := m["error"]; has {
			t.Errorf("happy-path body should NOT include error key, got %v", m)
		}
	})

	t.Run("error_path", func(t *testing.T) {
		dispatchErr := errors.New("container exited 1: candump: no such device")
		body, err := wrapCANResult("partial output before crash", dispatchErr)
		// Error must propagate so the agent's risk/retry layer fires.
		if err == nil {
			t.Error("wrapCANResult: expected propagated error, got nil")
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(body), &m); err != nil {
			t.Fatalf("body not JSON: %v\n%s", err, body)
		}
		if !strings.Contains(m["error"].(string), "no such device") {
			t.Errorf("error key missing original message: %v", m["error"])
		}
		if !strings.Contains(m["raw_output"].(string), "partial output") {
			t.Errorf("raw_output missing partial output: %v", m["raw_output"])
		}
		// status key should NOT appear in the error case (only
		// raw_output and error).
		if _, has := m["status"]; has {
			t.Errorf("error-path body should NOT include status key, got %v", m)
		}
	})
}
