package pocsag

import "testing"

func FuzzDecodeCodewordsHex(f *testing.F) {
	for _, s := range []string{"", "7CD215D8", "7A89C197", "00000000", "ZZ"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = DecodeCodewordsHex(s) })
}
