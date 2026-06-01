package jwtdecode

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "a.b.c", "eyJhbGciOiJIUzI1NiJ9.e30.x", "..", "a.b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}
