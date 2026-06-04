// SPDX-License-Identifier: AGPL-3.0-or-later

package tacacs

import (
	"encoding/hex"
	"testing"
)

// FuzzDecode asserts the parser never panics on arbitrary input. The packet
// bytes (hex-encoded) and the optional obfuscation key are both fuzzed.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{}, "")
	f.Add([]byte{0xc0, 0x01, 0x01, 0x00}, "secret")
	f.Fuzz(func(_ *testing.T, b []byte, key string) {
		_, _ = Decode(hex.EncodeToString(b), key) // must not panic
	})
}
