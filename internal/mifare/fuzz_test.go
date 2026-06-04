// SPDX-License-Identifier: AGPL-3.0-or-later

package mifare

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the Mifare dump/block decoders never panic on arbitrary
// input (raw bytes hex-encoded so every input reaches the parser).
func FuzzDecode(f *testing.F) {
	for _, b := range [][]byte{{}, {0x00}, make([]byte, 16), make([]byte, 1024)} {
		f.Add(b)
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		h := hex.EncodeToString(b)
		_, _ = DecodeDump(h)     // must not panic
		_, _ = DecodeBlock(h, 0) // must not panic
	})
}
