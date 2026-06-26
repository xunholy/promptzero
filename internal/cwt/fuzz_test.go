// SPDX-License-Identifier: AGPL-3.0-or-later

package cwt

import "testing"

// FuzzDecode throws arbitrary bytes at the CWT decoder — it parses an
// attacker-controllable token, so it must never panic.
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0xa7, 0x01, 0x75}) // start of the RFC claims map
	f.Add([]byte{0xd2, 0x84})       // COSE_Sign1 tag + array header, truncated
	f.Add([]byte{0xd0, 0x83})       // Encrypt0 tag + array header, truncated
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Decode(b)
	})
}
