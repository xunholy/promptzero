package zigbee

import "testing"

func FuzzDecodeAPSBytes(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00}, {0x08, 0x00}, {0x40, 0x01, 0x02}, {0xFF}} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = DecodeAPSBytes(b) })
}
