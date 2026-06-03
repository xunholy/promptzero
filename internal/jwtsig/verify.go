// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jwtsig verifies the HMAC signature of a JWS (JWT) against a candidate
// secret — the verification step jwt_decode deliberately leaves out. It is a
// web-pentest primitive: confirm a captured token is signed with a weak or
// guessed HS256/384/512 secret, or confirm the alg:none vulnerability.
//
// # Wrap-vs-native judgement
//
// Native. JWS HMAC verification is base64url-decode the header for the alg,
// recompute HMAC-SHA{256,384,512} over "header.payload", and constant-time
// compare to the signature segment — standard library only.
//
// # Verifiable / no confidently-wrong output
//
// Verified against the canonical jwt.io HS256 example token (secret
// "your-256-bit-secret"), the universal JWT reference vector. A non-HMAC
// algorithm (RS*/ES*/PS*/EdDSA) needs the issuer public key, not a shared
// secret, so it is reported as such rather than guessed; alg:none is reported
// as the vulnerability it is, never as a "valid" signature.
//
// # Covered / deferred
//
// Covered: HS256 / HS384 / HS512 verification and the alg:none / asymmetric
// classifications. Public-key verification — RS*/PS* (RSA), ES* (ECDSA) and
// EdDSA (Ed25519) — lives in VerifyPublicKey (verify_asym.go), which takes a
// PEM key/cert rather than a shared secret. JWE decryption remains out of scope.
package jwtsig

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"strings"
)

// Result is the outcome of a verification attempt.
type Result struct {
	Algorithm string `json:"algorithm"`
	Family    string `json:"family"` // "HMAC" | "none" | "asymmetric"
	Verified  bool   `json:"verified"`
	Note      string `json:"note,omitempty"`
}

// Verify checks a JWS compact token's HMAC signature against secret. For an
// HMAC alg it returns Verified=true iff the signature matches; for alg:none or
// an asymmetric alg it returns Verified=false with an explanatory Family/Note.
func Verify(token, secret string) (*Result, error) {
	token = strings.TrimSpace(token)
	token = strings.TrimPrefix(token, "Bearer ")
	token = strings.TrimPrefix(token, "bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		if len(parts) == 5 {
			return nil, fmt.Errorf("jwtsig: token has 5 segments (JWE, encrypted) — not a signed JWS")
		}
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
	alg := strings.ToUpper(strings.TrimSpace(hdr.Alg))
	r := &Result{Algorithm: hdr.Alg}

	var h func() hash.Hash
	switch alg {
	case "HS256":
		h = sha256.New
	case "HS384":
		h = sha512.New384
	case "HS512":
		h = sha512.New
	case "NONE", "":
		r.Family = "none"
		r.Note = "alg:none — the token is unsigned; a server that accepts it is vulnerable (CVE-class). No secret can 'verify' an unsigned token."
		return r, nil
	default:
		r.Family = "asymmetric"
		r.Note = fmt.Sprintf("%s is an asymmetric/public-key algorithm — verification needs the issuer's public key (X.509 / JWK), not a shared secret; not handled by this HMAC verifier", hdr.Alg)
		return r, nil
	}

	r.Family = "HMAC"
	signingInput := parts[0] + "." + parts[1]
	mac := hmac.New(h, []byte(secret))
	mac.Write([]byte(signingInput))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	r.Verified = hmac.Equal([]byte(expected), []byte(parts[2]))
	if !r.Verified {
		r.Note = "signature does not match this secret"
	}
	return r, nil
}
