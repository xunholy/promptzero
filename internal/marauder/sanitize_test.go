package marauder

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/clisafe"
)

// TestSanitizeArgStripsFramingBytes asserts that every byte that could
// terminate a Marauder CLI line early (\r \n \x00 \x03) plus the double-quote
// that delimits quoted fields is removed. AddSSID, Join, and SetSetting all
// share the helper — now sourced from the internal/clisafe package.
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
		{"mixed", "a\rb\nc\x00d\"e", "abcde"},
		{"empty", "", ""},
		{"spaces-preserved", "hello world", "hello world"},
		{"unicode-preserved", "café\r", "café"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := clisafe.SanitizeArg(c.in)
			if got != c.want {
				t.Fatalf("clisafe.SanitizeArg(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestValidateSelectIndices guards the Select{AP,Station,SSID} input filter
// against CLI-injection via a newline/semicolon-laden "indices" string.
func TestValidateSelectIndices(t *testing.T) {
	accept := []string{"all", "0", "1,2,3", "1 2 3", "10, 11 , 12", "42"}
	for _, s := range accept {
		if err := validateSelectIndices(s); err != nil {
			t.Errorf("validateSelectIndices(%q) unexpectedly rejected: %v", s, err)
		}
	}

	reject := []string{
		"1\n2",            // newline injection (primary attack)
		"1;reboot",        // shell-style separator
		"1\rscanall",      // carriage return injection
		"1\x00",           // NUL byte
		"all\nscanall",    // follow-on command after "all"
		"",                // empty — must not pass
		"abc",             // non-digits
		"1|2",             // pipe
		"1 && echo pwned", // ampersand
		"1\"",             // quote
	}
	for _, s := range reject {
		err := validateSelectIndices(s)
		if err == nil {
			t.Errorf("validateSelectIndices(%q) should have been rejected", s)
			continue
		}
		// Sanity-check the error mentions "indices" so callers can grep.
		if !strings.Contains(err.Error(), "indices") {
			t.Errorf("validateSelectIndices(%q) error %q missing 'indices' token", s, err)
		}
	}
}
