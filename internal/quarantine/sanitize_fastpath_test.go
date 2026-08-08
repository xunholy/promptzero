package quarantine

import (
	"strings"
	"testing"
)

// sanitizeRegexOnly is the pre-fast-path implementation: the four regex passes
// with no needsSanitize guard. It is the oracle the fast path must match
// byte-for-byte — if they ever diverge, the fast path is dropping (or keeping)
// something the real sanitizer would not.
func sanitizeRegexOnly(s string) string {
	s = ansiCSIRE.ReplaceAllString(s, "")
	s = ansiC1RE.ReplaceAllString(s, "")
	s = ansiC1UntermRE.ReplaceAllString(s, "")
	s = otherControlsRE.ReplaceAllString(s, "")
	return s
}

// TestSanitizeFastPath_MatchesRegexOnly pins the needsSanitize fast path to the
// regex-only oracle across adversarial inputs — every control byte, C1 runes,
// terminated/unterminated OSC sequences, CSI colour codes, and plain text. A
// mismatch here would mean the fast path opened an injection gap on the
// quarantine boundary.
func TestSanitizeFastPath_MatchesRegexOnly(t *testing.T) {
	cases := []string{
		"",
		"plain printable output: key = value, 42 rows",
		"tab\tnewline\ncr\r preserved",
		"esc CSI \x1b[31mred\x1b[0m tail",
		"osc terminated \x1b]0;title\x07 after",
		"osc unterminated \x1b]8;;http://x.example rest of line",
		"C1 rune CSI \u009b31m and OSC \u009dtitle",        // U+009B, U+009D
		"lone C1 controls \u0080\u0081\u009f between text", // U+0080-9F
		"del \x7f and null \x00 and vtab \x0b ff \x0c",
		"all lows: \x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x10\x1f",
		"utf8 kept: café — naïve — 日本語 — 🚀",
		"embedded > and </untrusted-hardware-output> literal",
		"\x1b",    // bare ESC
		"\x1b[",   // partial CSI
		"\u0080",  // bare C1 lead
		"a\x1b]b", // ESC OSC introducer, no terminator, no newline
	}
	for _, c := range cases {
		if got, want := SanitizeControlChars(c), sanitizeRegexOnly(c); got != want {
			t.Errorf("mismatch for %q:\n fast = %q\n regex= %q", c, got, want)
		}
	}
}

// TestNeedsSanitize_SupersetOfRegexMatches asserts the guard is a strict
// superset: for every single byte/rune the regexes could act on, needsSanitize
// must return true (else the fast path would skip a real match).
func TestNeedsSanitize_SupersetOfRegexMatches(t *testing.T) {
	// Every rune otherControlsRE matches, plus ESC, must trip needsSanitize.
	var triggers []rune
	triggers = append(triggers, 0x1b) // ESC introducer for the three ANSI regexes
	for r := rune(0x00); r <= 0x08; r++ {
		triggers = append(triggers, r)
	}
	triggers = append(triggers, 0x0b, 0x0c)
	for r := rune(0x0e); r <= 0x1f; r++ {
		triggers = append(triggers, r)
	}
	triggers = append(triggers, 0x7f)
	for r := rune(0x80); r <= 0x9f; r++ {
		triggers = append(triggers, r)
	}
	for _, r := range triggers {
		if !needsSanitize("safe" + string(r) + "safe") {
			t.Errorf("needsSanitize missed rune %U — regexes could match it but the fast path would skip", r)
		}
	}
	// The preserved whitespace and plain ASCII must NOT trip it.
	for _, s := range []string{"", "plain", "tab\t", "nl\n", "cr\r", "AZ az 09 !~"} {
		if needsSanitize(s) {
			t.Errorf("needsSanitize(%q) = true; want false (nothing to strip)", s)
		}
	}
}

func BenchmarkSanitizeClean(b *testing.B) {
	s := strings.Repeat("0 | -55 | 6 | AA:BB:CC:DD:EE:FF | OPEN | HomeWifi_2G\n", 20)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = SanitizeControlChars(s)
	}
}

func BenchmarkSanitizeDirty(b *testing.B) {
	s := strings.Repeat("\x1b[31mrow\x1b[0m \x00\x7f tail\n", 20)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = SanitizeControlChars(s)
	}
}

// FuzzSanitizeControlChars keeps the fast path and the regex-only oracle in
// lockstep on arbitrary input.
func FuzzSanitizeControlChars(f *testing.F) {
	for _, s := range []string{"", "plain", "\x1b[31m", "\x1b]8;;x\x07", "\u009b", "\x00\x7f\x9f", "café\x1b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if got, want := SanitizeControlChars(s), sanitizeRegexOnly(s); got != want {
			t.Errorf("fast path diverged from regex oracle for %q:\n fast = %q\n regex= %q", s, got, want)
		}
	})
}
