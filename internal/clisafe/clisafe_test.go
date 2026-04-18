package clisafe

import "testing"

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
