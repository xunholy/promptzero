package ndef

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0xD1}, {0xD1, 0x01, 0x0C, 0x55}, {0x10, 0x05}, {0x80}, {0xFF, 0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
