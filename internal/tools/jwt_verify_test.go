// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// TestJWTVerifyHandler_ES256 locks in the handler routing of an ES256 token to
// public-key verification (the asymmetric path added alongside RS*).
func TestJWTVerifyHandler_ES256(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	enc := base64.RawURLEncoding.EncodeToString
	hdr := enc([]byte(`{"alg":"ES256","typ":"JWT"}`))
	pl := enc([]byte(`{"sub":"alice"}`))
	si := hdr + "." + pl
	sum := sha256.Sum256([]byte(si))
	r, s, _ := ecdsa.Sign(rand.Reader, priv, sum[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	token := si + "." + enc(sig)

	der, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	out, err := jwtVerifyHandler(context.Background(), nil, map[string]any{
		"token": token, "public_key": pubPEM,
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m["verified"] != true {
		t.Errorf("ES256 token should verify via handler: %s", out)
	}

	// Without a public_key, an asymmetric token must error (not silently fail).
	if _, err := jwtVerifyHandler(context.Background(), nil, map[string]any{"token": token}); err == nil {
		t.Error("ES256 token without public_key should error")
	}
}
