// SPDX-License-Identifier: AGPL-3.0-or-later

package paseto

import "testing"

// FuzzDecode asserts Decode never panics on an arbitrary token string (the
// dot-split, base64url decode, and the message/signature length split).
func FuzzDecode(f *testing.F) {
	for _, s := range []string{tokS1, tokS2, tokE1, "v4.public.AAAA", "v1.local.", "", "...."} {
		f.Add(s)
	}
	f.Fuzz(func(_ *testing.T, token string) {
		_, _ = Decode(token) // must not panic
	})
}

// FuzzVerify asserts Verify never panics (it runs the PAE + Ed25519 path on
// well-formed-enough input, errors otherwise).
func FuzzVerify(f *testing.F) {
	for _, s := range []string{tokS1, tokS2, "v4.public.AAAA", "v2.public.x"} {
		f.Add(s, pubKey)
	}
	f.Fuzz(func(_ *testing.T, token, key string) {
		_, _ = Verify(token, key, "") // must not panic
	})
}
