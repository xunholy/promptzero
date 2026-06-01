package x509decode

import "testing"

func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "30", "3082", "MIIB", "-----BEGIN CERTIFICATE-----"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = Decode(s) })
}
