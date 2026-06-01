package j1850

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00, 0x01, 0x02, 0x03}, {0x68, 0x6A, 0xF1, 0x01, 0x00}, {0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
