package spf

import "testing"

// FuzzDecode drives arbitrary input through the parser to assert it never
// panics and never returns a nil error with a nil result.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"v=spf1 -all",
		googleSPF,
		githubSPF,
		"v=spf1 +all ~all a mx ptr include: redirect= ip4:/ exists:%{i}",
		`"v=spf1 ip4:1.2.3.4" " include:x ~all"`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		res, err := Decode(in)
		if err == nil && res == nil {
			t.Fatalf("Decode(%q): nil error and nil result", in)
		}
	})
}
