package web

import (
	"strings"
	"testing"
	"time"
)

// Pure helpers covered: sanitizePath (api_marauder.go), splitLines
// (api_marauder.go), and parseWhenWebStr (api.go). All three at 0%
// coverage before this file. parseWhenWebStr in particular has four
// distinct branches (Nd days form, ParseDuration form, RFC3339,
// error) plus negative-input guards.

func TestSanitizePath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Pass-through: spaces are legitimate on the SD card.
		{"/ext/nfc/My Card.nfc", "/ext/nfc/My Card.nfc"},
		{"", ""},
		// CR / LF / NUL / quote stripped.
		{"/ext\rnfc", "/extnfc"},
		{"/ext\nnfc", "/extnfc"},
		{"/ext\x00nfc", "/extnfc"},
		{`/ext/"injected".nfc`, "/ext/injected.nfc"},
		// All four stripped together.
		{"a\r\n\x00\"b", "ab"},
		// Tabs preserved (only CR/LF/NUL/quote are stripped).
		{"a\tb", "a\tb"},
	}
	for _, c := range cases {
		if got := sanitizePath(c.in); got != c.want {
			t.Errorf("sanitizePath(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestSplitLines(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"", []string{}},
		{"\n", []string{}},
		{"\r\n\r\n", []string{}},
		{"single", []string{"single"}},
		{"a\nb\nc", []string{"a", "b", "c"}},
		// CRLF normalised.
		{"a\r\nb\r\nc", []string{"a", "b", "c"}},
		// Trailing whitespace trimmed on each line.
		{"a   \nb\t\nc \t", []string{"a", "b", "c"}},
		// Blank lines dropped (including whitespace-only after trim).
		{"a\n   \nb", []string{"a", "b"}},
		{"\nleading-blank\nlast", []string{"leading-blank", "last"}},
	}
	for _, c := range cases {
		got := splitLines(c.in)
		if len(got) != len(c.want) {
			t.Errorf("splitLines(%q) = %v; want %v", c.in, got, c.want)
			continue
		}
		for i, w := range c.want {
			if got[i] != w {
				t.Errorf("splitLines(%q)[%d] = %q; want %q", c.in, i, got[i], w)
			}
		}
	}
}

func TestParseWhenWebStr_RelativeDuration(t *testing.T) {
	// time.ParseDuration accepts h/m/s/etc. Verify the resulting time
	// is in the past by the expected interval (within a 5s slop window
	// to absorb test scheduling jitter).
	before := time.Now()
	got, err := parseWhenWebStr("30m")
	if err != nil {
		t.Fatalf("parseWhenWebStr(30m): %v", err)
	}
	want := before.Add(-30 * time.Minute)
	if got.After(want.Add(5*time.Second)) || got.Before(want.Add(-5*time.Second)) {
		t.Errorf("parseWhenWebStr(30m) = %v; want ~%v", got, want)
	}

	got2, err := parseWhenWebStr("2h")
	if err != nil {
		t.Fatalf("parseWhenWebStr(2h): %v", err)
	}
	want2 := before.Add(-2 * time.Hour)
	if got2.After(want2.Add(5*time.Second)) || got2.Before(want2.Add(-5*time.Second)) {
		t.Errorf("parseWhenWebStr(2h) = %v; want ~%v", got2, want2)
	}
}

func TestParseWhenWebStr_DaysForm(t *testing.T) {
	// "<N>d" is not accepted by time.ParseDuration — verify the
	// dedicated days branch.
	before := time.Now()
	got, err := parseWhenWebStr("7d")
	if err != nil {
		t.Fatalf("parseWhenWebStr(7d): %v", err)
	}
	want := before.Add(-7 * 24 * time.Hour)
	if got.After(want.Add(5*time.Second)) || got.Before(want.Add(-5*time.Second)) {
		t.Errorf("parseWhenWebStr(7d) = %v; want ~%v", got, want)
	}

	// Uppercase D also accepted.
	got2, err := parseWhenWebStr("1D")
	if err != nil {
		t.Fatalf("parseWhenWebStr(1D): %v", err)
	}
	want2 := before.Add(-24 * time.Hour)
	if got2.After(want2.Add(5*time.Second)) || got2.Before(want2.Add(-5*time.Second)) {
		t.Errorf("parseWhenWebStr(1D) = %v; want ~%v", got2, want2)
	}
}

func TestParseWhenWebStr_RFC3339(t *testing.T) {
	want, err := time.Parse(time.RFC3339, "2026-01-15T10:30:00Z")
	if err != nil {
		t.Fatalf("setup time.Parse: %v", err)
	}
	got, err := parseWhenWebStr("2026-01-15T10:30:00Z")
	if err != nil {
		t.Fatalf("parseWhenWebStr(RFC3339): %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("parseWhenWebStr RFC3339 = %v; want %v", got, want)
	}
}

func TestParseWhenWebStr_Empty(t *testing.T) {
	for _, in := range []string{"", "   ", "\t"} {
		_, err := parseWhenWebStr(in)
		if err == nil {
			t.Errorf("parseWhenWebStr(%q) = nil; want empty-input error", in)
			continue
		}
		if !strings.Contains(err.Error(), "empty") {
			t.Errorf("parseWhenWebStr(%q) err = %v; want 'empty' in message", in, err)
		}
	}
}

func TestParseWhenWebStr_Unparseable(t *testing.T) {
	for _, in := range []string{"yesterday", "tomorrow at 3pm", "2026-99-99", "abc"} {
		_, err := parseWhenWebStr(in)
		if err == nil {
			t.Errorf("parseWhenWebStr(%q) = nil; want error", in)
			continue
		}
		if !strings.Contains(err.Error(), "cannot parse") {
			t.Errorf("parseWhenWebStr(%q) err = %v; want 'cannot parse' in message", in, err)
		}
	}
}

func TestParseWhenWebStr_NegativeDuration(t *testing.T) {
	// time.ParseDuration accepts "-30m" — guard rejects it with a
	// helpful nudge.
	_, err := parseWhenWebStr("-30m")
	if err == nil {
		t.Fatal("parseWhenWebStr(-30m) = nil; want negative-duration error")
	}
	if !strings.Contains(err.Error(), "negative") {
		t.Errorf("err = %v; want 'negative' in message", err)
	}

	// Negative days form too.
	_, err2 := parseWhenWebStr("-7d")
	if err2 == nil {
		t.Fatal("parseWhenWebStr(-7d) = nil; want negative-duration error")
	}
	if !strings.Contains(err2.Error(), "negative") {
		t.Errorf("err = %v; want 'negative' in message", err2)
	}
}
