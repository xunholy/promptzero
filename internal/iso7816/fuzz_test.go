package iso7816

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00, 0xA4}, {0x6F, 0x05}, {0x90, 0x00}, {0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
