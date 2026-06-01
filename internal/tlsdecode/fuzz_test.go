package tlsdecode

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x16, 0x03, 0x01}, {0x16, 0x03, 0x03, 0x00, 0x05}, {0x17}, {0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
