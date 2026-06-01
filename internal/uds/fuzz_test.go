package uds

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x7F}, {0x7F, 0x27}, {0x10}, {0x22, 0xF1}, {0x62}, {0xBA}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
