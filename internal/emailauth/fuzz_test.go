package emailauth

import "testing"

// FuzzDecode drives arbitrary input through the router to assert it never
// panics and never returns a nil error with a nil result.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", spfRec, dmarcRec, dkimRec, dkimNoV, "v=STSv1; id=x", "p=;k=;v="} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, in string) {
		res, err := Decode(in)
		if err == nil && res == nil {
			t.Fatalf("Decode(%q): nil error and nil result", in)
		}
	})
}
