// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pubPEMAny(t *testing.T, pub any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// signES builds an ES* JWS (raw r‖s) — the stdlib ecdsa is the reference signer.
func signES(t *testing.T, priv *ecdsa.PrivateKey, alg string, h crypto.Hash, payload string) string {
	t.Helper()
	hdr := b64([]byte(`{"alg":"` + alg + `","typ":"JWT"}`))
	pl := b64([]byte(payload))
	si := hdr + "." + pl
	sum := digest(h, si)
	r, s, err := ecdsa.Sign(rand.Reader, priv, sum)
	if err != nil {
		t.Fatal(err)
	}
	byteLen := (priv.Curve.Params().BitSize + 7) / 8
	sig := make([]byte, 2*byteLen)
	r.FillBytes(sig[:byteLen])
	s.FillBytes(sig[byteLen:])
	return si + "." + b64(sig)
}

func TestVerifyPublicKey_ES256(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := signES(t, priv, "ES256", crypto.SHA256, `{"sub":"alice"}`)
	pemKey := pubPEMAny(t, &priv.PublicKey)

	r, err := VerifyPublicKey(tok, pemKey)
	if err != nil || !r.Verified || r.Algorithm != "ES256" {
		t.Fatalf("ES256 should verify: %+v err=%v", r, err)
	}
	// Tamper.
	parts := strings.Split(tok, ".")
	parts[1] = b64([]byte(`{"sub":"admin"}`))
	if rt, _ := VerifyPublicKey(strings.Join(parts, "."), pemKey); rt.Verified {
		t.Error("tampered ES256 must not verify")
	}
	// Wrong key.
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if ro, _ := VerifyPublicKey(tok, pubPEMAny(t, &other.PublicKey)); ro.Verified {
		t.Error("ES256 must not verify under a different key")
	}
}

func TestVerifyPublicKey_ES384(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	tok := signES(t, priv, "ES384", crypto.SHA384, `{"sub":"bob"}`)
	if r, err := VerifyPublicKey(tok, pubPEMAny(t, &priv.PublicKey)); err != nil || !r.Verified {
		t.Fatalf("ES384 should verify: %+v err=%v", r, err)
	}
}

func TestVerifyPublicKey_PS256(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	hdr := b64([]byte(`{"alg":"PS256","typ":"JWT"}`))
	pl := b64([]byte(`{"sub":"carol"}`))
	si := hdr + "." + pl
	sum := digest(crypto.SHA256, si)
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, sum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatal(err)
	}
	tok := si + "." + b64(sig)
	if r, err := VerifyPublicKey(tok, pubPEMAny(t, &priv.PublicKey)); err != nil || !r.Verified {
		t.Fatalf("PS256 should verify: %+v err=%v", r, err)
	}
	// A PKCS1v15 (RS256) signature must NOT verify as PS256.
	rsSig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum)
	if rt, _ := VerifyPublicKey(si+"."+b64(rsSig), pubPEMAny(t, &priv.PublicKey)); rt.Verified {
		t.Error("PKCS1v15 signature must not verify under PS256")
	}
}

func TestVerifyPublicKey_EdDSA(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	hdr := b64([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	pl := b64([]byte(`{"sub":"dave"}`))
	si := hdr + "." + pl
	sig := ed25519.Sign(priv, []byte(si))
	tok := si + "." + b64(sig)
	r, err := VerifyPublicKey(tok, pubPEMAny(t, pub))
	if err != nil || !r.Verified || r.Algorithm != "EdDSA" {
		t.Fatalf("EdDSA should verify: %+v err=%v", r, err)
	}
	parts := strings.Split(tok, ".")
	parts[1] = b64([]byte(`{"sub":"root"}`))
	if rt, _ := VerifyPublicKey(strings.Join(parts, "."), pubPEMAny(t, pub)); rt.Verified {
		t.Error("tampered EdDSA must not verify")
	}
}

func TestVerifyPublicKey_KeyTypeMismatch(t *testing.T) {
	// ES256 token but an RSA key supplied → error.
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tok := signES(t, ec, "ES256", crypto.SHA256, `{}`)
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := VerifyPublicKey(tok, pubPEMAny(t, &rsaPriv.PublicKey)); err == nil {
		t.Error("ES256 token with RSA key should error")
	}
}

// TestVerifyPublicKey_RSStillWorks confirms the unified path still handles RS256
// (so jwt_verify can route every asymmetric alg through it).
func TestVerifyPublicKey_RSStillWorks(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	hdr := b64([]byte(`{"alg":"RS256","typ":"JWT"}`))
	pl := b64([]byte(`{"sub":"erin"}`))
	si := hdr + "." + pl
	sum := digest(crypto.SHA256, si)
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum)
	tok := si + "." + b64(sig)
	if r, err := VerifyPublicKey(tok, pubPEMAny(t, &priv.PublicKey)); err != nil || !r.Verified {
		t.Fatalf("RS256 via VerifyPublicKey should verify: %+v err=%v", r, err)
	}
}
