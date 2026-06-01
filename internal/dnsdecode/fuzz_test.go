package dnsdecode

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00}, {0x01, 0x02}, {0xFF, 0xFF}, {0x30, 0x82, 0x01, 0x01}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
