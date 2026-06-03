// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

// JWK is a JSON Web Key public key (RFC 7517) — the form an issuer publishes at
// /.well-known/jwks.json. Only the public-key members are read.
type JWK struct {
	Kty string `json:"kty"`           // "RSA" | "EC" | "OKP"
	Kid string `json:"kid,omitempty"` // key ID (matched against a token's kid)
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`   // RSA modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA exponent (base64url)
	Crv string `json:"crv,omitempty"` // EC/OKP curve
	X   string `json:"x,omitempty"`   // EC x / OKP public key (base64url)
	Y   string `json:"y,omitempty"`   // EC y (base64url)
}

// ConvertedKey is one JWK rendered to a PKIX PEM public key.
type ConvertedKey struct {
	Kid string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	Alg string `json:"alg,omitempty"`
	Use string `json:"use,omitempty"`
	Crv string `json:"crv,omitempty"`
	PEM string `json:"pem"`
}

// JWKToPEM converts a single JWK or a JWKS ({"keys":[…]}) JSON document into
// PKIX PEM public keys — the form jwt_verify consumes. RSA (kty=RSA), ECDSA
// (kty=EC, P-256/384/521) and Ed25519 (kty=OKP) public keys are supported;
// private members (d, p, q, …) are ignored.
func JWKToPEM(data string) ([]ConvertedKey, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return nil, fmt.Errorf("jwtsig: empty JWK input")
	}
	// A JWKS has a "keys" array; a bare JWK has a top-level "kty".
	var set struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal([]byte(data), &set); err == nil && len(set.Keys) > 0 {
		out := make([]ConvertedKey, 0, len(set.Keys))
		for i, k := range set.Keys {
			ck, cerr := convertJWK(k)
			if cerr != nil {
				return nil, fmt.Errorf("jwtsig: JWKS key %d (kid=%q): %w", i, k.Kid, cerr)
			}
			out = append(out, *ck)
		}
		return out, nil
	}
	var k JWK
	if err := json.Unmarshal([]byte(data), &k); err != nil {
		return nil, fmt.Errorf("jwtsig: not valid JWK/JWKS JSON: %w", err)
	}
	if k.Kty == "" {
		return nil, fmt.Errorf("jwtsig: not a JWK (missing \"kty\")")
	}
	ck, err := convertJWK(k)
	if err != nil {
		return nil, err
	}
	return []ConvertedKey{*ck}, nil
}

func convertJWK(k JWK) (*ConvertedKey, error) {
	ck := &ConvertedKey{Kid: k.Kid, Kty: k.Kty, Alg: k.Alg, Use: k.Use, Crv: k.Crv}
	var pub any
	switch k.Kty {
	case "RSA":
		if k.N == "" || k.E == "" {
			return nil, fmt.Errorf("RSA JWK missing n/e")
		}
		n, err := b64uBig(k.N)
		if err != nil {
			return nil, fmt.Errorf("RSA n: %w", err)
		}
		eb, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("RSA e: %w", err)
		}
		e := new(big.Int).SetBytes(eb)
		if !e.IsInt64() || e.Int64() < 2 || e.Int64() > (1<<31-1) {
			return nil, fmt.Errorf("RSA exponent out of range")
		}
		pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
	case "EC":
		curve, err := curveFor(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64uBig(k.X)
		if err != nil {
			return nil, fmt.Errorf("EC x: %w", err)
		}
		y, err := b64uBig(k.Y)
		if err != nil {
			return nil, fmt.Errorf("EC y: %w", err)
		}
		pub = &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("OKP curve %q unsupported (only Ed25519)", k.Crv)
		}
		xb, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("OKP x: %w", err)
		}
		if len(xb) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 key must be %d bytes, got %d", ed25519.PublicKeySize, len(xb))
		}
		pub = ed25519.PublicKey(xb)
	default:
		return nil, fmt.Errorf("unsupported kty %q (expected RSA, EC, or OKP)", k.Kty)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal %s key: %w", k.Kty, err)
	}
	ck.PEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return ck, nil
}

func curveFor(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("EC JWK curve %q unsupported (P-256/P-384/P-521)", crv)
	}
}

func b64uBig(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}

// SelectJWKPEM converts a JWK/JWKS and returns the PEM of the key whose kid
// matches want (or the sole/first key when want is empty or unmatched). Used by
// jwt_verify to accept a published JWK(S) directly as the key material.
func SelectJWKPEM(jwkJSON, wantKid string) (string, error) {
	keys, err := JWKToPEM(jwkJSON)
	if err != nil {
		return "", err
	}
	if len(keys) == 0 {
		return "", fmt.Errorf("jwtsig: no keys in JWK(S)")
	}
	if wantKid != "" {
		for _, k := range keys {
			if k.Kid == wantKid {
				return k.PEM, nil
			}
		}
	}
	return keys[0].PEM, nil
}
