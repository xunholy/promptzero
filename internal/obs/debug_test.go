package obs

import (
	"bytes"
	"runtime"
	"strings"
	"testing"
	"time"
)

// debug_test.go covers the rendering helpers in debug.go that
// previously had 0% coverage — pure functions with no I/O, so the
// tests are direct and cheap. Catches regressions where someone
// changes the box-drawing layout or the human-duration thresholds
// without realising operators rely on the exact format.

// TestHumanDuration pins the threshold transitions: sub-second
// shows full Duration string, 1s–60s shows "Xs", 1m–60m shows
// "Xm Ys", anything else shows "Xh Ym".
func TestHumanDuration(t *testing.T) {
	tests := []struct {
		in   time.Duration
		want string
	}{
		{0, "-"},
		{-1 * time.Second, "-"},
		{500 * time.Millisecond, "500ms"},
		{1 * time.Second, "1s"},
		{45 * time.Second, "45s"},
		{59 * time.Second, "59s"},
		{1 * time.Minute, "1m 0s"},
		{1*time.Minute + 30*time.Second, "1m 30s"},
		{59 * time.Minute, "59m 0s"},
		{1 * time.Hour, "1h 0m"},
		{2*time.Hour + 15*time.Minute, "2h 15m"},
	}
	for _, tc := range tests {
		if got := humanDuration(tc.in); got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRuneLen pins that runeLen counts Unicode code points, not
// bytes. Multibyte characters in the snapshot (mostly box-drawing
// characters and section dividers) must not skew the layout.
func TestRuneLen(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"a✓b", 3},
		{"├─┤", 3},
		{"emoji 🎉", 7},
	}
	for _, tc := range tests {
		if got := runeLen(tc.in); got != tc.want {
			t.Errorf("runeLen(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// TestTruncateRunes pins the multibyte-safe truncation: the result
// must contain n runes (not n bytes), and n ≤ 0 truncates to empty.
func TestTruncateRunes(t *testing.T) {
	tests := []struct {
		in   string
		n    int
		want string
	}{
		{"", 5, ""},
		{"abc", 5, "abc"},
		{"abcdef", 3, "abc"},
		{"a✓b✓c", 3, "a✓b"},
		{"hello", 0, ""},
		{"hello", -1, ""},
	}
	for _, tc := range tests {
		if got := truncateRunes(tc.in, tc.n); got != tc.want {
			t.Errorf("truncateRunes(%q, %d) = %q, want %q", tc.in, tc.n, got, tc.want)
		}
	}
}

// TestFormatTransport pins the three states the snapshot
// represents for a Flipper / Marauder transport: not configured
// (no port set), not connected (port set but link down), and
// connected (with optional extra info).
func TestFormatTransport(t *testing.T) {
	tests := []struct {
		name        string
		port        string
		up          bool
		extra       string
		want        string
		mustContain string
	}{
		{"empty port → not configured", "", false, "", "not configured", ""},
		{"empty port stays not configured even when up=true", "", true, "", "not configured", ""},
		{"port set, down", "/dev/ttyACM0", false, "", "/dev/ttyACM0 not connected", ""},
		{"port set, up, no extra", "/dev/ttyACM0", true, "", "/dev/ttyACM0 connected", ""},
		{"port set, up, with extra", "/dev/ttyACM0", true, "Momentum", "", "Momentum"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := formatTransport(tc.port, tc.up, tc.extra)
			if tc.want != "" && got != tc.want {
				t.Errorf("formatTransport(%q, %v, %q) = %q, want %q", tc.port, tc.up, tc.extra, got, tc.want)
			}
			if tc.mustContain != "" && !strings.Contains(got, tc.mustContain) {
				t.Errorf("formatTransport(%q, %v, %q) = %q, want it to contain %q", tc.port, tc.up, tc.extra, got, tc.mustContain)
			}
		})
	}
}

// TestShortSHA pins the helper that truncates a vcs.revision string
// to its first 7 characters — short SHAs are the convention git
// itself uses.
func TestShortSHA(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"a", "a"},
		{"abc1234", "abc1234"},
		{"abc12345", "abc1234"},
		{"deadbeef0123456789", "deadbee"},
	}
	for _, tc := range tests {
		if got := shortSHA(tc.in); got != tc.want {
			t.Errorf("shortSHA(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestRender_FullSnapshot exercises the main rendering path with a
// realistic snapshot. Asserts that the output contains every
// section header plus the expected values — doesn't pin the exact
// box-drawing layout (which is intentionally not load-bearing) but
// catches a regression where a section is silently dropped.
func TestRender_FullSnapshot(t *testing.T) {
	snap := DebugSnapshot{
		BuildVersion: "v0.63.0",
		GoVersion:    "go1.25.0",
		Platform:     "linux/amd64",
		Uptime:       3 * time.Minute,
		TraceID:      "trace-abc-123",
		PersonaName:  "default",
		PersonaTools: 100,
		PersonaAllow: 80,
		FlipperPort:  "/dev/ttyACM0",
		FlipperUp:    true,
		FlipperModel: "Momentum",
		MarauderPort: "/dev/ttyUSB0",
		MarauderUp:   true,
		AuditDBPath:  "/tmp/audit.db",
		AuditRows:    42,
		SessionID:    "session-xyz",
		Goroutines:   25,
		HeapMB:       12.3,
		SysMB:        45.6,
		LastGCAgo:    500 * time.Millisecond,
		LastTools: []ToolSample{
			{At: time.Date(2026, 5, 11, 10, 30, 0, 0, time.UTC), Tool: "wifi_scan_ap", Risk: "medium", Err: false, Duration: 15 * time.Second},
			{At: time.Date(2026, 5, 11, 10, 31, 0, 0, time.UTC), Tool: "subghz_receive", Risk: "medium", Err: true, Duration: 100 * time.Millisecond},
		},
		OfflineMode: true,
	}
	var buf bytes.Buffer
	snap.Render(&buf, 68)
	got := buf.String()

	// Each section header must appear.
	for _, want := range []string{"Runtime", "State", "Goroutines", "Last tool calls"} {
		if !strings.Contains(got, want) {
			t.Errorf("Render output missing section %q\n%s", want, got)
		}
	}
	// Key fields rendered.
	for _, want := range []string{
		"v0.63.0", "go1.25.0", "linux/amd64",
		"trace-abc-123 (current turn)",
		"default (allowlist 80/100 tools)",
		"/dev/ttyACM0 connected (Momentum)",
		"/dev/ttyUSB0 connected",
		"/tmp/audit.db (42 entries)",
		"session-xyz",
		"OFFLINE",
		"wifi_scan_ap",
		"subghz_receive",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("Render output missing %q\n%s", want, got)
		}
	}

	// Tool with err=true should render ✗; success-mark ◦ should also appear.
	if !strings.Contains(got, "✗") {
		t.Errorf("Render output missing ✗ marker for failed tool")
	}
	if !strings.Contains(got, "◦") {
		t.Errorf("Render output missing ◦ marker for successful tool")
	}
}

// TestRender_MinimalSnapshot exercises the rendering path with
// almost no fields set — defaults should kick in (persona name
// "default", no traceID line, no last-tool-calls block).
func TestRender_MinimalSnapshot(t *testing.T) {
	snap := DebugSnapshot{
		Uptime:     1 * time.Second,
		Goroutines: 5,
	}
	var buf bytes.Buffer
	snap.Render(&buf, 68)
	got := buf.String()

	if !strings.Contains(got, "default") {
		t.Errorf("Render output missing default persona on minimal snapshot:\n%s", got)
	}
	if strings.Contains(got, "Trace ID") {
		t.Errorf("Render output should not include Trace ID line when empty")
	}
	if strings.Contains(got, "Last tool calls") {
		t.Errorf("Render output should not include Last tool calls section when slice empty")
	}
	if strings.Contains(got, "not configured") == false {
		// Flipper + Marauder both unset — should both say "not configured".
		t.Errorf("Render output should mark unset transports as 'not configured':\n%s", got)
	}
}

// TestRender_WidthFloor enforces the minimum-width floor. Render
// silently bumps anything under 40 up to 40 so a too-narrow
// terminal still produces a usable box rather than a glitched
// negative-width pad.
func TestRender_WidthFloor(t *testing.T) {
	snap := DebugSnapshot{Goroutines: 1}
	var buf bytes.Buffer
	snap.Render(&buf, 10) // intentionally too narrow
	got := buf.String()
	// The horizontal rule should be at least 40 dashes wide.
	if !strings.Contains(got, strings.Repeat("─", 40)) {
		t.Errorf("Render with width=10 should have floored to 40-wide rule; got:\n%s", got)
	}
}

// TestCollectRuntime pins the runtime collector's contract: it
// returns sensible values (non-negative goroutines + memory, a
// non-empty version + platform). The exact numbers are
// environment-dependent — assert on shape, not magnitude.
func TestCollectRuntime(t *testing.T) {
	goroutines, heapMB, sysMB, _, version, plat := CollectRuntime()
	if goroutines <= 0 {
		t.Errorf("CollectRuntime goroutines = %d, want >0", goroutines)
	}
	if heapMB < 0 {
		t.Errorf("CollectRuntime heapMB = %v, want ≥0", heapMB)
	}
	if sysMB < 0 {
		t.Errorf("CollectRuntime sysMB = %v, want ≥0", sysMB)
	}
	if version == "" || !strings.HasPrefix(version, "go") {
		t.Errorf("CollectRuntime version = %q, want a go-prefixed string", version)
	}
	if plat == "" || !strings.Contains(plat, "/") {
		t.Errorf("CollectRuntime plat = %q, want GOOS/GOARCH", plat)
	}
	// Sanity: returned plat should match runtime.GOOS/GOARCH.
	wantPlat := runtime.GOOS + "/" + runtime.GOARCH
	if plat != wantPlat {
		t.Errorf("CollectRuntime plat = %q, want %q", plat, wantPlat)
	}
}

// TestRender_SanitizesDeviceReportedModel pins that a device-reported string
// (the Flipper firmware model) carrying ANSI/OSC escapes — which a compromised
// device could emit to inject terminal-control sequences into the operator's
// /debug box — is stripped before rendering.
func TestRender_SanitizesDeviceReportedModel(t *testing.T) {
	snap := DebugSnapshot{
		FlipperPort:  "/dev/ttyACM0",
		FlipperUp:    true,
		FlipperModel: "Evil\x1b[31m\x1b]0;pwn\x07\nINJECTED",
	}
	var buf bytes.Buffer
	snap.Render(&buf, 68)
	got := buf.String()

	if strings.Contains(got, "\x1b]0;pwn") || strings.Contains(got, "\x1b[31m") || strings.Contains(got, "\x07") {
		t.Errorf("device model ANSI/OSC escape survived into /debug output:\n%q", got)
	}
	// The printable text survives (control chars removed, not the whole value).
	if !strings.Contains(got, "Evil") || !strings.Contains(got, "INJECTED") {
		t.Errorf("device model text dropped by sanitization: %q", got)
	}
}
