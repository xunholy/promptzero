// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"
)

func rsaJWKS(t *testing.T, priv *rsa.PrivateKey, kid string) string {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	eb := big.NewInt(int64(priv.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eb)
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"alg":"RS256","use":"sig","n":%q,"e":%q}]}`, kid, n, e)
}

func TestJWKToPEMHandler(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	out, err := jwkToPEMHandler(context.Background(), nil, map[string]any{"jwk": rsaJWKS(t, priv, "k9")})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m["count"].(float64) != 1 {
		t.Fatalf("count: %v", m["count"])
	}
	keys, _ := m["keys"].([]any)
	k0, _ := keys[0].(map[string]any)
	pemStr, _ := k0["pem"].(string)
	if k0["kid"] != "k9" || pemStr == "" || pemStr[:5] != "-----" {
		t.Errorf("bad converted key: %+v", k0)
	}
}

// TestJWTVerifyHandler_JWKS is the end-to-end integration: an RS256 token whose
// header carries a kid, verified by passing the issuer's JWKS straight to
// jwt_verify (no manual PEM conversion).
func TestJWTVerifyHandler_JWKS(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	enc := base64.RawURLEncoding.EncodeToString
	hdr := enc([]byte(`{"alg":"RS256","typ":"JWT","kid":"k9"}`))
	pl := enc([]byte(`{"sub":"alice"}`))
	si := hdr + "." + pl
	sum := sha256.Sum256([]byte(si))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, sum[:])
	token := si + "." + enc(sig)

	out, err := jwtVerifyHandler(context.Background(), nil, map[string]any{
		"token": token, "public_key": rsaJWKS(t, priv, "k9"),
	})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(out), &m)
	if m["verified"] != true {
		t.Errorf("RS256 token should verify via JWKS public_key: %s", out)
	}
}
