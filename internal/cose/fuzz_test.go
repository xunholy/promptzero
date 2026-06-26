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
