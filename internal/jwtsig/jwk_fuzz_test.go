// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import "testing"

// FuzzJWKToPEM asserts the JWK/JWKS parser never panics on arbitrary JSON (it
// parses an untrusted /.well-known/jwks.json document).
func FuzzJWKToPEM(f *testing.F) {
	seeds := []string{
		`{"kty":"RSA","n":"AQAB","e":"AQAB"}`,
		`{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`,
		`{"kty":"OKP","crv":"Ed25519","x":"AA"}`,
		`{"keys":[]}`, `{}`, `[]`, `null`, ``, `{"kty":"RSA","n":"!!!","e":"!!!"}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = JWKToPEM(s) // must not panic
	})
}
