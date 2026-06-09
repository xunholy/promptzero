package dkim

import "testing"

// FuzzDecode drives arbitrary input through the parser to assert it never
// panics and never returns a nil error with a nil result.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"p=",
		"v=DKIM1; k=rsa; p=" + rsa1024P,
		"k=ed25519; p=" + ed25519P,
		"v=DKIM1; k=rsa; t=y:s; h=sha1:sha256; p=" + rsa512P,
		"garbage; ; ;==;p",
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
