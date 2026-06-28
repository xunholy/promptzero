// SPDX-License-Identifier: AGPL-3.0-or-later

package cose

import "testing"

// FuzzDecodeMessage throws arbitrary bytes at the COSE message decoder — it
// parses an attacker-controllable artifact, so it must never panic.
func FuzzDecodeMessage(f *testing.F) {
	f.Add([]byte{0xd2, 0x84})                   // Sign1 tag + array, truncated
	f.Add([]byte{0xd0, 0x83})                   // Encrypt0 tag + array, truncated
	f.Add([]byte{0x84, 0x43, 0xa1, 0x01, 0x26}) // untagged, partial
	f.Add([]byte{0xd2, 0x80})                   // tag18 + empty array (regression)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeMessage(b)
	})
}

// FuzzDecodeKey throws arbitrary bytes at the COSE_Key decoder. A COSE key is
// attacker-controllable too (it rides inside WebAuthn attestation objects and
// COSE messages), so the parser must never panic.
func FuzzDecodeKey(f *testing.F) {
	f.Add([]byte{0xa1, 0x01, 0x02})             // {1: 2} kty=EC2, truncated
	f.Add([]byte{0xa5, 0x01, 0x02, 0x20, 0x01}) // partial EC2 key
	f.Add([]byte{0xa0})                         // empty map
	f.Add([]byte{0x01, 0x02})                   // not a map
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeKey(b)
	})
}
