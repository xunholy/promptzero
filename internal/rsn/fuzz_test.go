package rsn

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x01}, {0x01, 0x00}, {0x30, 0x14}, {0x01, 0x00, 0, 0x0F, 0xAC, 4}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
