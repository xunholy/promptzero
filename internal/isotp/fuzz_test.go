package isotp

import "testing"

func FuzzDecodeFrame(f *testing.F) {
	for _, s := range [][]byte{{}, {0x02, 0x10}, {0x10, 0x00}, {0x10}, {0x21}, {0x30}, {0x00}, {0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeFrame(b) })
}
