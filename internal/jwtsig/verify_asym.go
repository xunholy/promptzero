// SPDX-License-Identifier: AGPL-3.0-or-later

package jwtsig

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256 for crypto.Hash.New
	_ "crypto/sha512" // register SHA-384/512
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
)

// VerifyPublicKey verifies an asymmetric JWS signature against a PEM-encoded
// public key (or X.509 certificate), dispatching on the token's alg header:
//
//   - RS256/384/512 — RSA PKCS#1 v1.5
//   - PS256/384/512 — RSA-PSS (Azure AD / Microsoft Entra; salt length = hash)
//   - ES256/384/512 — ECDSA over P-256/P-384/P-521 (Apple and many IdPs; the
//     JWS signature is the raw r‖s, fixed-width, not ASN.1 DER)
//   - EdDSA          — Ed25519 (no pre-hash; verifies over the signing input)
//
// It is the asymmetric counterpart to Verify (HMAC). RS256 aside, these are the
// algorithms a real-world captured token is most likely to use; this is what
// lets jwt_verify check any of them against the issuer's published key.
func VerifyPublicKey(token, pemPublicKey string) (*Result, error) {
	alg, signingInput, sig, err := splitJWS(token)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	r := &Result{Algorithm: alg, Family: "asymmetric"}
	upper := strings.ToUpper(strings.TrimSpace(alg))

	switch {
	case strings.HasPrefix(upper, "RS"), strings.HasPrefix(upper, "PS"):
		h, err := hashForJWA(upper)
		if err != nil {
			return nil, err
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwtsig: token alg is %s (RSA) but the supplied key is %T", alg, pub)
		}
		sum := digest(h, signingInput)
		if upper[0] == 'P' { // PS* = RSA-PSS
			r.Verified = rsa.VerifyPSS(rsaPub, h, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}) == nil
		} else { // RS* = RSA PKCS#1 v1.5
			r.Verified = rsa.VerifyPKCS1v15(rsaPub, h, sum, sig) == nil
		}

	case strings.HasPrefix(upper, "ES"):
		h, err := hashForJWA(upper)
		if err != nil {
			return nil, err
		}
		ecPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwtsig: token alg is %s (ECDSA) but the supplied key is %T", alg, pub)
		}
		// JWS ECDSA signature is r‖s, each the curve's byte size (RFC 7518 §3.4).
		byteLen := (ecPub.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*byteLen {
			r.Note = fmt.Sprintf("signature length %d != expected %d for this curve (r‖s); wrong key/curve or tampered", len(sig), 2*byteLen)
			return r, nil
		}
		rInt := new(big.Int).SetBytes(sig[:byteLen])
		sInt := new(big.Int).SetBytes(sig[byteLen:])
		r.Verified = ecdsa.Verify(ecPub, digest(h, signingInput), rInt, sInt)

	case upper == "EDDSA":
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("jwtsig: token alg is EdDSA (Ed25519) but the supplied key is %T", pub)
		}
		// Ed25519 hashes internally; verify over the raw signing input.
		r.Verified = ed25519.Verify(edPub, []byte(signingInput), sig)

	default:
		return nil, fmt.Errorf("jwtsig: VerifyPublicKey handles RS*/PS*/ES*/EdDSA; token alg is %q", alg)
	}

	if !r.Verified && r.Note == "" {
		r.Note = "signature does not verify against this public key (wrong key, tampered token, or wrong algorithm)"
	}
	return r, nil
}

// splitJWS trims an optional Bearer prefix, splits the compact token, and
// returns the alg, the "header.payload" signing input, and the decoded signature.
func splitJWS(token string) (alg, signingInput string, sig []byte, err error) {
	token = strings.TrimSpace(token)
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		if len(parts) == 5 {
			return "", "", nil, fmt.Errorf("jwtsig: token has 5 segments (JWE, encrypted) — not a signed JWS")
		}
		return "", "", nil, fmt.Errorf("jwtsig: expected 3 dot-separated segments (JWS); got %d", len(parts))
	}
	hdrBytes, derr := base64.RawURLEncoding.DecodeString(parts[0])
	if derr != nil {
		return "", "", nil, fmt.Errorf("jwtsig: header is not valid base64url: %w", derr)
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if jerr := json.Unmarshal(hdrBytes, &hdr); jerr != nil {
		return "", "", nil, fmt.Errorf("jwtsig: header is not valid JSON: %w", jerr)
	}
	sig, derr = base64.RawURLEncoding.DecodeString(parts[2])
	if derr != nil {
		return "", "", nil, fmt.Errorf("jwtsig: signature is not valid base64url: %w", derr)
	}
	return hdr.Alg, parts[0] + "." + parts[1], sig, nil
}

// hashForJWA maps a JWA algorithm name to its digest hash (the trailing bits).
func hashForJWA(upper string) (crypto.Hash, error) {
	switch {
	case strings.HasSuffix(upper, "256"):
		return crypto.SHA256, nil
	case strings.HasSuffix(upper, "384"):
		return crypto.SHA384, nil
	case strings.HasSuffix(upper, "512"):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("jwtsig: cannot determine hash for alg %q", upper)
	}
}

func digest(h crypto.Hash, signingInput string) []byte {
	hh := h.New()
	hh.Write([]byte(signingInput))
	return hh.Sum(nil)
}

// parsePublicKey accepts a PKIX/SPKI public key (RSA / ECDSA / Ed25519), a
// PKCS#1 RSA public key, or an X.509 certificate (its public key is used).
func parsePublicKey(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(pemStr)))
	if block == nil {
		return nil, fmt.Errorf("jwtsig: public_key is not valid PEM")
	}
	if k, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return k, nil
	}
	if c, err := x509.ParseCertificate(block.Bytes); err == nil {
		return c.PublicKey, nil
	}
	return nil, fmt.Errorf("jwtsig: unrecognised PEM public-key format (expected PKIX/SPKI, PKCS#1, or an X.509 certificate)")
}
