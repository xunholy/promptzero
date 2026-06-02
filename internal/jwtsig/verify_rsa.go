// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // register SHA-384/512
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
)

// VerifyRSA verifies an RS256/RS384/RS512 JWS signature against a PEM-encoded
// RSA public key — the asymmetric counterpart to Verify (which handles the HS*
// HMAC family). RS256 is the dominant production JWT signing algorithm (the
// default for Auth0, Okta, and most identity providers), so this is what lets
// jwt_verify check a real-world token's authenticity against the issuer's
// public key (typically published at /.well-known/jwks.json as a cert/SPKI).
//
// The PEM may be a PKIX/SPKI "PUBLIC KEY", a PKCS#1 "RSA PUBLIC KEY", or an
// X.509 "CERTIFICATE" (its public key is used). ES*/PS*/EdDSA are out of scope.
func VerifyRSA(token, pemPublicKey string) (*Result, error) {
	token = strings.TrimSpace(token)
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwtsig: expected 3 dot-separated segments (JWS); got %d", len(parts))
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwtsig: header is not valid base64url: %w", err)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("jwtsig: header is not valid JSON: %w", err)
	}
	var h crypto.Hash
	switch strings.ToUpper(strings.TrimSpace(hdr.Alg)) {
	case "RS256":
		h = crypto.SHA256
	case "RS384":
		h = crypto.SHA384
	case "RS512":
		h = crypto.SHA512
	default:
		return nil, fmt.Errorf("jwtsig: VerifyRSA handles RS256/RS384/RS512 only; token alg is %q", hdr.Alg)
	}
	pub, err := parseRSAPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwtsig: signature is not valid base64url: %w", err)
	}
	hasher := h.New()
	hasher.Write([]byte(parts[0] + "." + parts[1]))
	r := &Result{Algorithm: hdr.Alg, Family: "RSA"}
	r.Verified = rsa.VerifyPKCS1v15(pub, h, hasher.Sum(nil), sig) == nil
	if !r.Verified {
		r.Note = "signature does not verify against this public key (wrong key, tampered token, or not RSA-PKCS1v15)"
	}
	return r, nil
}

// parseRSAPublicKey accepts a PKIX/SPKI public key, a PKCS#1 RSA public key, or
// an X.509 certificate (whose public key must be RSA).
func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, fmt.Errorf("jwtsig: public_key is not valid PEM")
	}
	if k, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rp, ok := k.(*rsa.PublicKey); ok {
			return rp, nil
		}
		return nil, fmt.Errorf("jwtsig: PEM public key is not RSA")
	}
	if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return k, nil
	}
	if c, err := x509.ParseCertificate(block.Bytes); err == nil {
		if rp, ok := c.PublicKey.(*rsa.PublicKey); ok {
			return rp, nil
		}
		return nil, fmt.Errorf("jwtsig: certificate public key is not RSA")
	}
	return nil, fmt.Errorf("jwtsig: unrecognised PEM public-key format (expected PKIX/SPKI, PKCS#1, or an X.509 certificate)")
}
