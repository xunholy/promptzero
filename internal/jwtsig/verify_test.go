// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import "testing"

// The canonical jwt.io HS256 example token + its secret — the universal JWT
// reference vector.
const (
	hs256Token  = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	hs256Secret = "your-256-bit-secret"
)

func TestVerify_HS256_Canonical(t *testing.T) {
	r, err := Verify(hs256Token, hs256Secret)
	if err != nil {
		t.Fatal(err)
	}
	if r.Algorithm != "HS256" || r.Family != "HMAC" {
		t.Errorf("alg/family = %s/%s, want HS256/HMAC", r.Algorithm, r.Family)
	}
	if !r.Verified {
		t.Error("canonical jwt.io HS256 token should verify with its secret")
	}
}

func TestVerify_HS256_WrongSecret(t *testing.T) {
	r, err := Verify(hs256Token, "wrong-secret")
	if err != nil {
		t.Fatal(err)
	}
	if r.Verified {
		t.Error("wrong secret must not verify")
	}
	if r.Note == "" {
		t.Error("expected a mismatch note")
	}
}

func TestVerify_BearerPrefix(t *testing.T) {
	r, err := Verify("Bearer "+hs256Token, hs256Secret)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Verified {
		t.Error("Bearer-prefixed token should verify")
	}
}

func TestVerify_AlgNone(t *testing.T) {
	// alg:none token (header {"alg":"none","typ":"JWT"}), empty signature.
	tok := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0In0."
	r, err := Verify(tok, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Family != "none" || r.Verified {
		t.Errorf("alg:none = %+v, want family none / not verified", r)
	}
}

func TestVerify_Asymmetric(t *testing.T) {
	// RS256 header {"alg":"RS256","typ":"JWT"} — reported as asymmetric.
	tok := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.AAAA"
	r, err := Verify(tok, "irrelevant")
	if err != nil {
		t.Fatal(err)
	}
	if r.Family != "asymmetric" || r.Verified {
		t.Errorf("RS256 = %+v, want family asymmetric / not verified", r)
	}
}

func TestVerify_Errors(t *testing.T) {
	for _, tok := range []string{"", "onlyonesegment", "two.segments", "a.b.c.d.e.f"} {
		if _, err := Verify(tok, "x"); err == nil {
			t.Errorf("%q: expected error", tok)
		}
	}
}
