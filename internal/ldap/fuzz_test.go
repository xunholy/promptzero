package ldap

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "00", "0102", "FFFF", "30820101", "FF00FF00"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}
