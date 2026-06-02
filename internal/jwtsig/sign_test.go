// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import "testing"

// TestSign_Canonical reproduces the canonical jwt.io HS256 token from its exact
// payload + secret — the round-trip anchor against the published reference.
func TestSign_Canonical(t *testing.T) {
	payload := `{"sub":"1234567890","name":"John Doe","iat":1516239022}`
	tok, err := Sign(payload, "HS256", hs256Secret)
	if err != nil {
		t.Fatal(err)
	}
	if tok != hs256Token {
		t.Errorf("forged token:\n  %s\nwant canonical:\n  %s", tok, hs256Token)
	}
}

// TestSign_VerifyRoundTrip: a forged token verifies with its secret, across algs.
func TestSign_RoundTrip(t *testing.T) {
	payload := `{"sub":"admin","admin":true}`
	for _, alg := range []string{"HS256", "HS384", "HS512"} {
		tok, err := Sign(payload, alg, "s3cr3t")
		if err != nil {
			t.Fatalf("%s: %v", alg, err)
		}
		r, err := Verify(tok, "s3cr3t")
		if err != nil {
			t.Fatalf("%s verify: %v", alg, err)
		}
		if !r.Verified || r.Algorithm != alg {
			t.Errorf("%s: forged token did not verify (%+v)", alg, r)
		}
		// Wrong secret must not verify the forgery.
		if w, _ := Verify(tok, "wrong"); w.Verified {
			t.Errorf("%s: forged token verified with the wrong secret", alg)
		}
	}
}

func TestSign_AlgNone(t *testing.T) {
	tok, err := Sign(`{"sub":"admin"}`, "none", "")
	if err != nil {
		t.Fatal(err)
	}
	// alg:none token ends with a trailing dot and an empty signature.
	if tok[len(tok)-1] != '.' {
		t.Errorf("alg:none token should end with an empty signature segment: %s", tok)
	}
	r, err := Verify(tok, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.Family != "none" {
		t.Errorf("forged alg:none classified as %s, want none", r.Family)
	}
}

func TestSign_Errors(t *testing.T) {
	if _, err := Sign(`not json`, "HS256", "k"); err == nil {
		t.Error("invalid JSON payload should error")
	}
	if _, err := Sign(`{}`, "RS256", "k"); err == nil {
		t.Error("RS256 signing (asymmetric) should error")
	}
}
