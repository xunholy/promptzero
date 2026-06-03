// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"testing"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// parsePEMPub parses a PKIX PEM public key for comparison.
func parsePEMPub(t *testing.T, p string) any {
	t.Helper()
	blk, _ := pem.Decode([]byte(p))
	if blk == nil {
		t.Fatalf("not PEM: %q", p)
	}
	k, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestJWKToPEM_RSA round-trips an RSA JWK against the stdlib key (the anchor),
// and pins the e="AQAB" exponent to 65537.
func TestJWKToPEM_RSA(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	jwk := fmt.Sprintf(`{"kty":"RSA","kid":"k1","n":%q,"e":%q}`,
		b64u(priv.N.Bytes()),
		b64u(big2bytes(priv.E)))
	keys, err := JWKToPEM(jwk)
	if err != nil || len(keys) != 1 {
		t.Fatalf("convert: %v (%d keys)", err, len(keys))
	}
	pub, ok := parsePEMPub(t, keys[0].PEM).(*rsa.PublicKey)
	if !ok || pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		t.Errorf("RSA round-trip mismatch")
	}
	if pub.E != 65537 {
		t.Errorf("e=AQAB should be 65537, got %d", pub.E)
	}
	if keys[0].Kid != "k1" {
		t.Errorf("kid lost: %q", keys[0].Kid)
	}
}

func TestJWKToPEM_EC(t *testing.T) {
	for _, c := range []struct {
		crv   string
		curve elliptic.Curve
	}{{"P-256", elliptic.P256()}, {"P-384", elliptic.P384()}, {"P-521", elliptic.P521()}} {
		priv, _ := ecdsa.GenerateKey(c.curve, rand.Reader)
		jwk := fmt.Sprintf(`{"kty":"EC","crv":%q,"x":%q,"y":%q}`, c.crv, b64u(priv.X.Bytes()), b64u(priv.Y.Bytes()))
		keys, err := JWKToPEM(jwk)
		if err != nil {
			t.Fatalf("%s: %v", c.crv, err)
		}
		pub, ok := parsePEMPub(t, keys[0].PEM).(*ecdsa.PublicKey)
		if !ok || pub.X.Cmp(priv.X) != 0 || pub.Y.Cmp(priv.Y) != 0 {
			t.Errorf("%s EC round-trip mismatch", c.crv)
		}
	}
}

func TestJWKToPEM_Ed25519(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	jwk := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q}`, b64u(pub))
	keys, err := JWKToPEM(jwk)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parsePEMPub(t, keys[0].PEM).(ed25519.PublicKey)
	if !ok || !got.Equal(pub) {
		t.Errorf("Ed25519 round-trip mismatch")
	}
}

func TestJWKToPEM_JWKSAndSelect(t *testing.T) {
	r, _ := rsa.GenerateKey(rand.Reader, 2048)
	e, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwks := fmt.Sprintf(`{"keys":[%s,%s]}`,
		fmt.Sprintf(`{"kty":"RSA","kid":"rsa1","n":%q,"e":"AQAB"}`, b64u(r.N.Bytes())),
		fmt.Sprintf(`{"kty":"EC","kid":"ec1","crv":"P-256","x":%q,"y":%q}`, b64u(e.X.Bytes()), b64u(e.Y.Bytes())))
	keys, err := JWKToPEM(jwks)
	if err != nil || len(keys) != 2 {
		t.Fatalf("JWKS: %v (%d)", err, len(keys))
	}
	// SelectJWKPEM by kid.
	p, err := SelectJWKPEM(jwks, "ec1")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := parsePEMPub(t, p).(*ecdsa.PublicKey); !ok {
		t.Error("select ec1 should yield an EC key")
	}
}

func TestJWKToPEM_Errors(t *testing.T) {
	for _, bad := range []string{
		"", "not json", `{}`, `{"kty":"oct","k":"AA"}`,
		`{"kty":"RSA"}`, `{"kty":"EC","crv":"P-999","x":"AA","y":"AA"}`,
		`{"kty":"OKP","crv":"X25519","x":"AA"}`,
	} {
		if _, err := JWKToPEM(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func big2bytes(e int) []byte {
	// minimal big-endian bytes of a positive exponent (65537 -> 01 00 01 = "AQAB").
	var b []byte
	for e > 0 {
		b = append([]byte{byte(e & 0xff)}, b...)
		e >>= 8
	}
	return b
}
