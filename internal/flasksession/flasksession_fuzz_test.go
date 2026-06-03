// SPDX-License-Identifier: AGPL-3.0-or-later

package flasksession

import "testing"

// FuzzDecode asserts the cookie parser never panics on arbitrary input (it
// parses an untrusted Set-Cookie value: base64url segments + optional zlib).
func FuzzDecode(f *testing.F) {
	for _, s := range []string{
		v1Cookie, v2Cookie, v3Cookie, "", ".", "..", "a.b.c",
		".AAAA.ah-2tQ.sig", "eyJ9.x.y", ".zzzz.ah.s",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = Decode(s) // must not panic (incl. malformed zlib)
	})
}
