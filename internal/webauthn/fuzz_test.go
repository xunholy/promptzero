// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthn

import "testing"

// FuzzDecode throws arbitrary bytes at the authData decoder — it parses an
// attacker-controllable structure (a captured registration/assertion), so it
// must never panic regardless of malformed lengths or CBOR.
func FuzzDecode(f *testing.F) {
	f.Add(make([]byte, 37))
	f.Add(append(make([]byte, 37), 0x40)) // AT flag set but truncated would be caught
	f.Add([]byte{0xA1, 0x01, 0x02})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = Decode(b)
	})
}
