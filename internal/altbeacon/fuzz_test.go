package altbeacon

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"1BFF1801BEAC2F234454CF6D4A0FADF2F4911BA9FFA600010002C500", "BEAC", "1801BEAC", "DD", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}
