package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/xunholy/promptzero/internal/risk"
)

func TestFormatConfirmPreview_LowRiskReturnsEmpty(t *testing.T) {
	req := ConfirmRequest{Tool: "subghz_receive", Risk: risk.Low, Input: json.RawMessage(`{}`)}
	if got := FormatConfirmPreview(req); got != "" {
		t.Fatalf("low-risk preview should be empty, got:\n%s", got)
	}
}

func TestFormatConfirmPreview_HighRiskIncludesRiskAndTool(t *testing.T) {
	req := ConfirmRequest{
		Tool:  "wifi_deauth",
		Risk:  risk.High,
		Input: json.RawMessage(`{"duration_seconds":30}`),
	}
	got := FormatConfirmPreview(req)
	if !strings.Contains(got, "About to run wifi_deauth") {
		t.Errorf("missing title: %s", got)
	}
	if !strings.Contains(got, "risk: high") {
		t.Errorf("missing risk line: %s", got)
	}
	if !strings.Contains(got, "duration_seconds: 30") {
		t.Errorf("missing duration field: %s", got)
	}
	// Box framing must be present.
	if !strings.Contains(got, "┌") || !strings.Contains(got, "└") {
		t.Errorf("box framing missing: %s", got)
	}
}

func TestFormatConfirmPreview_FrequencyRendersInMHz(t *testing.T) {
	req := ConfirmRequest{
		Tool:  "subghz_transmit",
		Risk:  risk.Critical,
		Input: json.RawMessage(`{"frequency":433920000}`),
	}
	got := FormatConfirmPreview(req)
	if !strings.Contains(got, "433920000 Hz") {
		t.Errorf("raw Hz missing: %s", got)
	}
	if !strings.Contains(got, "433.920 MHz") {
		t.Errorf("MHz annotation missing: %s", got)
	}
}

func TestFormatConfirmPreview_HandlesMalformedJSON(t *testing.T) {
	// A tool with non-JSON input (shouldn't happen but be defensive)
	// still renders the risk + tool name without panicking.
	req := ConfirmRequest{
		Tool:  "flipper_raw_cli",
		Risk:  risk.Critical,
		Input: json.RawMessage(`not-json-at-all`),
	}
	got := FormatConfirmPreview(req)
	if !strings.Contains(got, "flipper_raw_cli") {
		t.Errorf("tool name missing on malformed input: %s", got)
	}
	if !strings.Contains(got, "risk: critical") {
		t.Errorf("risk missing on malformed input: %s", got)
	}
}

func TestFormatConfirmPreview_LongValuesTruncate(t *testing.T) {
	// Attackers (or novice users) can pass giant strings. Preview must
	// not blow out the terminal — check the visual (rune) width, not
	// byte length, since our box glyphs are multi-byte UTF-8.
	big := strings.Repeat("X", 500)
	payload, _ := json.Marshal(map[string]string{"data": big})
	req := ConfirmRequest{Tool: "rfid_write", Risk: risk.High, Input: payload}
	got := FormatConfirmPreview(req)
	const maxCols = 80
	for _, line := range strings.Split(got, "\n") {
		if runeCount(line) > maxCols {
			t.Errorf("line exceeded %d runes (%d): %q", maxCols, runeCount(line), line)
		}
	}
}

func runeCount(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

// TestTruncDisplay_PreservesMultiByteRunes locks the UTF-8 safety
// guarantee. Naive byte-slicing s[:n] could split a multi-byte rune
// (e.g. emoji or accented char straddling position n) and produce
// invalid UTF-8. truncDisplay counts runes so a boundary character
// is preserved intact.
func TestTruncDisplay_PreservesMultiByteRunes(t *testing.T) {
	t.Run("ascii_under_limit", func(t *testing.T) {
		if got := truncDisplay("hello", 10); got != "hello" {
			t.Errorf("truncDisplay = %q, want %q", got, "hello")
		}
	})
	t.Run("ascii_truncates_with_ellipsis", func(t *testing.T) {
		got := truncDisplay("abcdefghij", 5)
		if got != "abcde…" {
			t.Errorf("truncDisplay = %q, want %q", got, "abcde…")
		}
	})
	t.Run("multibyte_at_boundary_intact", func(t *testing.T) {
		// "café" is 4 runes / 5 bytes (é = 2 bytes). Truncating to
		// 4 runes must not chop the é mid-rune.
		got := truncDisplay("café-suffix", 4)
		want := "café…"
		if got != want {
			t.Errorf("truncDisplay = %q (% x), want %q", got, []byte(got), want)
		}
		// Verify the result is valid UTF-8 (no replacement runes).
		if !utf8.ValidString(got) {
			t.Errorf("output is not valid UTF-8: %q (% x)", got, []byte(got))
		}
	})
	t.Run("emoji_boundary", func(t *testing.T) {
		// Emoji are 4 bytes each; cut between two emojis preserves
		// the surviving half intact.
		got := truncDisplay("🦀🦀🦀🦀", 2)
		want := "🦀🦀…"
		if got != want {
			t.Errorf("truncDisplay = %q, want %q", got, want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("output is not valid UTF-8: %q", got)
		}
	})
	t.Run("zero_n_empty", func(t *testing.T) {
		if got := truncDisplay("anything", 0); got != "" {
			t.Errorf("truncDisplay(_, 0) = %q, want empty", got)
		}
	})
}

func TestFormatConfirmPreview_OnlyKnownFieldsSurface(t *testing.T) {
	req := ConfirmRequest{
		Tool:  "wifi_evil_portal_start",
		Risk:  risk.Critical,
		Input: json.RawMessage(`{"filename":"starbucks.html","internal_id":"abc123"}`),
	}
	got := FormatConfirmPreview(req)
	if !strings.Contains(got, "filename: starbucks.html") {
		t.Errorf("known field missing: %s", got)
	}
	if strings.Contains(got, "internal_id") {
		t.Errorf("unknown field leaked into preview: %s", got)
	}
}

// ConfirmDelayGate tests.

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }
func (f *fakeClock) advance(d time.Duration) {
	f.t = f.t.Add(d)
}

func newFakeGate(delay time.Duration) (*ConfirmDelayGate, *fakeClock) {
	c := &fakeClock{t: time.Now()}
	g := &ConfirmDelayGate{delay: delay, now: c.now}
	return g, c
}

func TestConfirmDelayGate_ClosedBeforeShow(t *testing.T) {
	g, _ := newFakeGate(2 * time.Second)
	if g.Open() {
		t.Fatalf("gate should be closed before Show()")
	}
	if g.Remaining() != 2*time.Second {
		t.Fatalf("Remaining = %v, want 2s", g.Remaining())
	}
}

func TestConfirmDelayGate_ClosedDuringDelay(t *testing.T) {
	g, clk := newFakeGate(2 * time.Second)
	g.Show()
	if g.Open() {
		t.Fatalf("gate should be closed immediately after Show")
	}
	clk.advance(1 * time.Second)
	if g.Open() {
		t.Fatalf("gate should still be closed at 1s (delay is 2s)")
	}
	if r := g.Remaining(); r <= 0 || r > 1*time.Second {
		t.Fatalf("Remaining at 1s elapsed = %v, want ~1s", r)
	}
}

func TestConfirmDelayGate_OpensAfterDelay(t *testing.T) {
	g, clk := newFakeGate(2 * time.Second)
	g.Show()
	clk.advance(2 * time.Second)
	if !g.Open() {
		t.Fatalf("gate should open exactly at delay boundary")
	}
	// Well past the boundary.
	clk.advance(5 * time.Second)
	if !g.Open() {
		t.Fatalf("gate should remain open past delay")
	}
}

func TestConfirmDelayGate_ShowResetsCountdown(t *testing.T) {
	g, clk := newFakeGate(2 * time.Second)
	g.Show()
	clk.advance(1500 * time.Millisecond)
	g.Show() // e.g. prompt was redrawn after resize
	if g.Open() {
		t.Fatalf("gate should close again after re-Show()")
	}
	clk.advance(500 * time.Millisecond)
	if g.Open() {
		t.Fatalf("500ms into new window — should still be closed")
	}
	clk.advance(1600 * time.Millisecond)
	if !g.Open() {
		t.Fatalf("gate should open 2s after re-Show()")
	}
}

// MinimumConfirmDelay is exported — make sure it's in the expected
// range. Hard-coding the value across tests and docs would be fragile.
func TestMinimumConfirmDelay_InReasonableRange(t *testing.T) {
	if MinimumConfirmDelay < 500*time.Millisecond || MinimumConfirmDelay > 10*time.Second {
		t.Fatalf("MinimumConfirmDelay = %v; expected between 0.5s and 10s", MinimumConfirmDelay)
	}
}
