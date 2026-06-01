package emv

import "testing"

func FuzzParseBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x6F}, {0x6F, 0x1A}, {0x9F, 0x10}, {0x5F, 0x2D, 0x02}, {0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = ParseBytes(b) })
}
