// SPDX-License-Identifier: AGPL-3.0-or-later

package nrf24

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the parser never panics on arbitrary input (raw bytes
// hex-encoded so every input reaches the binary parser).
func FuzzDecode(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00}, {0x01, 0x02, 0x03, 0x04}, {0xff, 0xff, 0xff, 0xff}} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		_, _ = Decode(hex.EncodeToString(b), DecodeOptions{}) // must not panic
	})
}
