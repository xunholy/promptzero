package dmarc

import "testing"

// FuzzDecode drives arbitrary input through the parser to assert it never
// panics and never returns a nil error with a nil result.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		"",
		"v=DMARC1; p=none",
		"v=DMARC1; p=reject; pct=50; sp=quarantine; adkim=s; aspf=r; rua=mailto:a@b.com; ruf=mailto:c@d.com; fo=0:1:d:s; ri=3600",
		"v=DMARC1",
		"v=spf1 -all",
		"v=DMARC1; pct=abc; ri=xyz; p=weird",
		";;;==;p=;v=DMARC1",
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
