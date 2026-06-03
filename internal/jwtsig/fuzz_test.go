// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import "testing"

// FuzzVerify asserts the HMAC verifier never panics on an arbitrary token /
// secret (it parses an untrusted compact token: base64url segments + JSON header).
func FuzzVerify(f *testing.F) {
	seeds := []string{
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig",
		"a.b.c",
		"....",
		"only-one-segment",
		"a.b.c.d.e", // 5 segments (JWE shape)
		"",
		"eyJhbGciOiJub25lIn0..",
	}
	for _, s := range seeds {
		f.Add(s, "secret")
	}
	f.Fuzz(func(t *testing.T, token, secret string) {
		_, _ = Verify(token, secret) // must not panic
	})
}

// FuzzVerifyPublicKey asserts the asymmetric verifier never panics on an
// arbitrary token / PEM key. Random inputs fail fast at PEM/segment parsing;
// the heavy crypto runs only for the (rare) well-formed case, so it stays cheap.
func FuzzVerifyPublicKey(f *testing.F) {
	seeds := []struct{ tok, key string }{
		{"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhIn0.AA", "-----BEGIN PUBLIC KEY-----\nMFkw\n-----END PUBLIC KEY-----"},
		{"a.b.c", ""},
		{"eyJhbGciOiJSUzI1NiJ9.e30.AAAA", "not a pem"},
		{"eyJhbGciOiJFZERTQSJ9.e30.", "-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----"},
		{"", ""},
	}
	for _, s := range seeds {
		f.Add(s.tok, s.key)
	}
	f.Fuzz(func(t *testing.T, token, pemKey string) {
		_, _ = VerifyPublicKey(token, pemKey) // must not panic
	})
}
