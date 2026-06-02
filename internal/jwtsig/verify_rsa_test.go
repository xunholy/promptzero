// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

// signRS256 builds an RS256 JWS over the payload with priv — the test's
// reference signer (Go's crypto/rsa is the authoritative oracle).
func signRS256(t *testing.T, priv *rsa.PrivateKey, payload string) string {
	t.Helper()
	hdr := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pl := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := hdr + "." + pl
	h := crypto.SHA256.New()
	h.Write([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func pubPEM(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func TestVerifyRSA_RoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tok := signRS256(t, priv, `{"sub":"alice","admin":false}`)
	pem := pubPEM(t, priv)

	r, err := VerifyRSA(tok, pem)
	if err != nil {
		t.Fatal(err)
	}
	if r.Algorithm != "RS256" || r.Family != "RSA" || !r.Verified {
		t.Errorf("valid RS256 token should verify: %+v", r)
	}

	// Tampered payload must fail.
	parts := strings.Split(tok, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice","admin":true}`))
	tampered := strings.Join(parts, ".")
	if rt, _ := VerifyRSA(tampered, pem); rt.Verified {
		t.Error("tampered token must not verify")
	}

	// A different key must fail.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if ro, _ := VerifyRSA(tok, pubPEM(t, other)); ro.Verified {
		t.Error("token must not verify under a different public key")
	}
}

func TestVerifyRSA_Errors(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pem := pubPEM(t, priv)
	// HS256 token -> not an RS* alg.
	if _, err := VerifyRSA(hs256Token, pem); err == nil {
		t.Error("HS256 token should error in VerifyRSA")
	}
	// Bad PEM.
	if _, err := VerifyRSA(signRS256(t, priv, `{}`), "not a pem"); err == nil {
		t.Error("invalid PEM should error")
	}
}
