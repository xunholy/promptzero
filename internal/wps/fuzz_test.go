package wps

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x10}, {0x10, 0x4A}, {0x10, 0x4A, 0x00, 0x01}, {0xDD, 0x06, 0x00, 0x50, 0xF2, 0x04}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytes(b) })
}
