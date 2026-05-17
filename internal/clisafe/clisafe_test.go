package clisafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// TestSanitizeArgStripsFramingBytes asserts the full set of bytes that
// could terminate or escape a quoted CLI argument is removed, and that
// benign content (spaces, unicode) survives unchanged.
func TestSanitizeArgStripsFramingBytes(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "PromptZero", "PromptZero"},
		{"cr", "abc\rdef", "abcdef"},
		{"lf", "abc\ndef", "abcdef"},
		{"nul", "abc\x00def", "abcdef"},
		{"etx", "abc\x03def", "abcdef"},
		{"quote", `abc"def`, "abcdef"},
		{"all-bytes", "a\rb\nc\x00d\x03e\"f", "abcdef"},
		{"empty", "", ""},
		{"spaces-preserved", "hello world", "hello world"},
		{"unicode-preserved", "café\r", "café"},
		{"only-strip-bytes", "\r\n\x00\x03\"", ""},
		{"leading-stripped", "\rhello", "hello"},
		{"trailing-stripped", "hello\n", "hello"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SanitizeArg(c.in)
			if got != c.want {
				t.Fatalf("SanitizeArg(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestTruncateWithEllipsis_ShortInputUnchanged(t *testing.T) {
	cases := []struct {
		s   string
		n   int
		out string
	}{
		{"hello", 10, "hello"},
		{"", 5, ""},
		{"abc", 3, "abc"}, // exactly n is still <= n; no truncation
	}
	for _, c := range cases {
		if got := TruncateWithEllipsis(c.s, c.n); got != c.out {
			t.Errorf("TruncateWithEllipsis(%q, %d) = %q; want %q", c.s, c.n, got, c.out)
		}
	}
}

func TestTruncateWithEllipsis_LongInputAppendsMarker(t *testing.T) {
	got := TruncateWithEllipsis("abcdefghij", 5)
	if got != "abcde"+EllipsisMarker {
		t.Errorf("got %q; want 'abcde…'", got)
	}
}

func TestTruncateWithEllipsis_UTF8BoundaryWalkBack(t *testing.T) {
	// "…" is 3 bytes (0xE2 0x80 0xA6). Build a string of 4 ASCII
	// + "…" + tail so n=5 lands mid-rune (byte 5 == 0x80, a
	// continuation byte). The helper must walk back to byte 4
	// (the start of '…') and cut there, then append the marker.
	s := "abcd" + "…" + "tail"
	got := TruncateWithEllipsis(s, 5)
	want := "abcd" + EllipsisMarker
	if got != want {
		t.Errorf("got %q; want %q (walk-back must drop the split rune)", got, want)
	}
}

func TestTruncateWithEllipsis_ZeroOrNegativeReturnsMarker(t *testing.T) {
	for _, n := range []int{0, -1, -100} {
		got := TruncateWithEllipsis("anything here is plenty long", n)
		if got != EllipsisMarker {
			t.Errorf("n=%d: got %q; want %q", n, got, EllipsisMarker)
		}
	}
	if got := TruncateWithEllipsis("", 0); got != "" {
		t.Errorf("empty source: got %q; want empty", got)
	}
}

func TestTruncateWithEllipsis_AlwaysValidUTF8(t *testing.T) {
	// Pin the safety invariant: every output of the helper is valid
	// UTF-8 regardless of where the cap lands in the input. Probe
	// across the whole range of cap positions for an emoji-heavy
	// string.
	s := strings.Repeat("🎉", 50) // 4-byte rune × 50 = 200 bytes
	for n := 0; n < len(s)+5; n++ {
		got := TruncateWithEllipsis(s, n)
		if !utf8.ValidString(got) {
			t.Errorf("n=%d produced invalid UTF-8: %q", n, got)
		}
	}
}
