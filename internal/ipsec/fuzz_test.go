// SPDX-License-Identifier: AGPL-3.0-or-later

package ipsec

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the ESP and AH parsers never panic on arbitrary input
// (raw bytes hex-encoded so every input reaches the binary parser).
func FuzzDecode(f *testing.F) {
	for _, s := range [][]byte{{}, {0x00}, {0x01, 0x02, 0x03, 0x04}, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		h := hex.EncodeToString(b)
		_, _ = DecodeESP(h, DecodeOpts{}) // must not panic
		_, _ = DecodeAH(h)                // must not panic
	})
}
