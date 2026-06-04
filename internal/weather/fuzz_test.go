// SPDX-License-Identifier: AGPL-3.0-or-later

package weather

import "testing"

// FuzzDecodeBytes asserts the 433 MHz weather-frame decoder never panics on
// arbitrary bit/byte payloads — checksum gating and field slicing must hold.
func FuzzDecodeBytes(f *testing.F) {
	for _, b := range [][]byte{{}, {0x00}, {0x9e, 0x00, 0x4f, 0x2b, 0x12}, {0xff, 0xff, 0xff, 0xff, 0xff}} {
		f.Add(b)
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = DecodeBytes(b) // must not panic
	})
}
