// SPDX-License-Identifier: AGPL-3.0-or-later

package sshkey

import "testing"

// FuzzDecode asserts the parser never panics on arbitrary input — the base64
// decode, SSH-wire length-prefixed walk, and comment scan must reject
// truncated / hostile length fields with an error, not crash.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{edB64, edEncB64, rsaB64, "", "notb64@@@", "aGVsbG8="} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, s string) {
		_, _ = Decode(s) // must not panic
	})
}
