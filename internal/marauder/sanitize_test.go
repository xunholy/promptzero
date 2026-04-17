package marauder

import "testing"

// TestSanitizeArgStripsFramingBytes asserts that every byte that could
// terminate a Marauder CLI line early (\r \n \x00) plus the double-quote
// that delimits quoted fields is removed. The exact same characters need
// to be scrubbed for AddSSID, Join, and SetSetting; the helper is shared.
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
		{"quote", `abc"def`, "abcdef"},
		{"mixed", "a\rb\nc\x00d\"e", "abcde"},
		{"empty", "", ""},
		{"spaces-preserved", "hello world", "hello world"},
		{"unicode-preserved", "café\r", "café"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeArg(c.in)
			if got != c.want {
				t.Fatalf("sanitizeArg(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}
