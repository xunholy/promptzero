package ieee802154

import "testing"

func FuzzDecodeBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x01, 0x88}, {0x41, 0x88, 0x00}, {0x03}, {0xFF, 0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeBytesWithOptions(b, DecodeOptions{}) })
}
