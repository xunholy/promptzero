// SPDX-License-Identifier: AGPL-3.0-or-later

package gtp

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the decoder never panics on arbitrary frame bytes — a
// hand-written length-prefixed binary parser must reject malformed/truncated
// input with an error, not crash (the untrusted pcap-and-paste DoS surface).
func FuzzDecode(f *testing.F) {
	for _, n := range []int{0, 1, 2, 4, 8, 12, 20, 40, 64, 128} {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i*7 + 1)
		}
		f.Add(b)
	}
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Decode(hex.EncodeToString(data)) // must not panic
	})
}
