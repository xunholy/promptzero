// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jwtdecode decodes JSON Web Tokens (JWT) — the
// dominant API auth token format in modern web stacks. Used
// pervasively in OAuth 2.0 / OIDC bearer-token flows, REST
// API authentication, single-sign-on assertion exchange,
// service-to-service mTLS-bypass tokens, and almost every
// modern identity-provider integration since ~2015.
//
// # Wrap-vs-native judgement
//
// Native. JWT is defined by the public RFC 7519 (JWT) +
// RFC 7515 (JSON Web Signature, the Compact Serialization
// envelope) + RFC 7516 (JSON Web Encryption). The Compact
// Serialization is three base64url-encoded segments joined
// by '.' for JWS or five for JWE. Each segment is either
// JSON (header + payload) or opaque bytes (signature).
// Pasting a token from `curl -H 'Authorization: Bearer
// <token>'`, a browser cookie, an OAuth flow trace, or an
// API debugger is enough — no key material required.
//
// # What this package covers
//
//   - Three-segment JWS Compact Serialization parsing
//     (header.payload.signature). The base64url decoder
//     handles both padded and unpadded inputs and the URL-
//     safe alphabet (- and _ in place of + and /).
//   - Five-segment JWE Compact Serialization detection.
//     The Spec labels the token as encrypted and surfaces
//     the header (which is plaintext) but does not decrypt
//     the body — that requires key material out of scope
//     for a pure-decode primitive.
//   - JWS header field decode (RFC 7515 §4): alg (algorithm
//     name + family classification: none / HS* HMAC / RS*
//     RSA-PKCS1 / ES* ECDSA / PS* RSA-PSS / EdDSA), typ,
//     cty (content type), kid (key ID), x5t (X.509 cert
//     thumbprint), x5t#S256 (SHA-256 thumbprint), x5c
//     (X.509 cert chain count), jku (JWK Set URL), jwk
//     (embedded JWK), and crit (critical extensions list).
//   - JWT payload decode (RFC 7519 §4) — registered claims:
//     iss (issuer), sub (subject), aud (audience, string or
//     array), exp (expiration), nbf (not-before), iat
//     (issued-at), jti (JWT ID). Standard timestamp claims
//     are surfaced both as the raw Unix epoch value and as
//     RFC 3339 strings for human inspection. Custom /
//     private / public claims are preserved in a free-form
//     map so OIDC claims (sub, email, given_name, etc.) and
//     application-specific claims survive.
//   - **Security flags** that operators routinely care about:
//   - alg_none — set when alg == "none", a famous JWT
//     vulnerability class (CVE-2015-2951 and friends).
//   - signature_missing — set when the signature segment
//     is empty even though alg says it shouldn't be.
//   - expired / not_yet_valid — computed from exp / nbf
//     against current wall clock.
//   - hours_until_expiry / hours_since_expired —
//     numeric triage values for at-a-glance assessment.
//   - clock_skew_grace — none applied here; operators
//     reading expired-by-30-seconds tokens should know.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - **Signature verification**: this is a pure decode
//     primitive. Verifying HS256/RS256/ES256/EdDSA signatures
//     requires the operator's signing key (HMAC secret or
//     verifier public key). A follow-up Spec can layer on
//     verification when a key-store is wired in.
//   - **JWE body decryption**: needs the recipient's private
//     key. The header is decoded; the encrypted_key,
//     iv, ciphertext, and tag segments are surfaced as raw
//     base64url strings.
//   - JWS JSON Serialization (the non-Compact form with
//     per-recipient signature objects) — rare in practice;
//     deferred until real captures surface.
//   - Audience-vs-expected matching — that's a policy
//     decision; this Spec surfaces the audience field for
//     the caller to compare against their expected value.
//   - Key-store integration — out of scope; operators feed
//     in tokens, this Spec hands back structured field
//     views.
package jwtdecode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Token is the decoded view of a JWT.
//
// Format reports which Compact Serialization variant was
// detected. For JWE the payload + Claims fields stay nil
// and only the header + RawSegments[1..4] (encrypted_key,
// iv, ciphertext, tag) are surfaced.
type Token struct {
	Format             string                 `json:"format"`
	Header             map[string]interface{} `json:"header"`
	HeaderAlgorithm    string                 `json:"header_algorithm,omitempty"`
	HeaderAlgFamily    string                 `json:"header_algorithm_family,omitempty"`
	HeaderType         string                 `json:"header_type,omitempty"`
	HeaderContentType  string                 `json:"header_content_type,omitempty"`
	HeaderKeyID        string                 `json:"header_key_id,omitempty"`
	HeaderX5T          string                 `json:"header_x5t,omitempty"`
	HeaderX5TSHA256    string                 `json:"header_x5t_s256,omitempty"`
	HeaderX5CCount     int                    `json:"header_x5c_count,omitempty"`
	HeaderJKU          string                 `json:"header_jku,omitempty"`
	HeaderCriticalExt  []string               `json:"header_critical_extensions,omitempty"`
	Payload            map[string]interface{} `json:"payload,omitempty"`
	Claims             *RegisteredClaims      `json:"registered_claims,omitempty"`
	SignaturePresent   bool                   `json:"signature_present"`
	SignatureLength    int                    `json:"signature_length"`
	SignatureBase64URL string                 `json:"signature_base64url,omitempty"`
	JWESegments        *JWESegments           `json:"jwe_segments,omitempty"`
	Security           *SecurityFlags         `json:"security"`
}

// RegisteredClaims is the RFC 7519 §4.1 set of standard
// claims. Audience may be a single string or an array; we
// surface both shapes in Audience.
type RegisteredClaims struct {
	Issuer           string   `json:"issuer,omitempty"`
	Subject          string   `json:"subject,omitempty"`
	Audience         []string `json:"audience,omitempty"`
	ExpiresAt        int64    `json:"expires_at_unix,omitempty"`
	ExpiresAtRFC3339 string   `json:"expires_at,omitempty"`
	NotBefore        int64    `json:"not_before_unix,omitempty"`
	NotBeforeRFC3339 string   `json:"not_before,omitempty"`
	IssuedAt         int64    `json:"issued_at_unix,omitempty"`
	IssuedAtRFC3339  string   `json:"issued_at,omitempty"`
	JWTID            string   `json:"jwt_id,omitempty"`
}

// SecurityFlags is the triage view operators want at a glance.
type SecurityFlags struct {
	AlgNone           bool `json:"alg_none"`
	SignatureMissing  bool `json:"signature_missing"`
	Expired           bool `json:"expired,omitempty"`
	NotYetValid       bool `json:"not_yet_valid,omitempty"`
	HoursUntilExpiry  int  `json:"hours_until_expiry,omitempty"`
	HoursSinceExpired int  `json:"hours_since_expired,omitempty"`
}

// JWESegments carries the four post-header JWE segments
// surfaced as raw base64url for callers that want them.
type JWESegments struct {
	EncryptedKeyBase64URL string `json:"encrypted_key_base64url,omitempty"`
	IVBase64URL           string `json:"iv_base64url,omitempty"`
	CiphertextBase64URL   string `json:"ciphertext_base64url,omitempty"`
	AuthTagBase64URL      string `json:"auth_tag_base64url,omitempty"`
}

// Decode parses a JWT (JWS or JWE compact serialization).
func Decode(token string) (*Token, error) {
	s := strings.TrimSpace(token)
	if s == "" {
		return nil, fmt.Errorf("jwtdecode: empty token")
	}
	// Some tokens come with a leading "Bearer " prefix from
	// an Authorization header — strip it.
	s = strings.TrimPrefix(s, "Bearer ")
	s = strings.TrimPrefix(s, "bearer ")
	parts := strings.Split(s, ".")
	switch len(parts) {
	case 3:
		return decodeJWS(parts)
	case 5:
		return decodeJWE(parts)
	}
	return nil, fmt.Errorf(
		"jwtdecode: expected 3 segments (JWS) or 5 segments (JWE); got %d",
		len(parts))
}

func decodeJWS(parts []string) (*Token, error) {
	t := &Token{Format: "JWS (Compact Serialization)"}
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwtdecode: header base64url: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &t.Header); err != nil {
		return nil, fmt.Errorf("jwtdecode: header JSON: %w", err)
	}
	enrichHeader(t)
	payloadBytes, err := decodeBase64URL(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwtdecode: payload base64url: %w", err)
	}
	if err := json.Unmarshal(payloadBytes, &t.Payload); err != nil {
		return nil, fmt.Errorf("jwtdecode: payload JSON: %w", err)
	}
	t.Claims = extractClaims(t.Payload)
	sig, err := decodeBase64URL(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwtdecode: signature base64url: %w", err)
	}
	t.SignatureLength = len(sig)
	t.SignaturePresent = len(sig) > 0
	if t.SignaturePresent {
		t.SignatureBase64URL = parts[2]
	}
	t.Security = buildSecurityFlags(t)
	return t, nil
}

func decodeJWE(parts []string) (*Token, error) {
	t := &Token{Format: "JWE (Compact Serialization)"}
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwtdecode: header base64url: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &t.Header); err != nil {
		return nil, fmt.Errorf("jwtdecode: header JSON: %w", err)
	}
	enrichHeader(t)
	t.JWESegments = &JWESegments{
		EncryptedKeyBase64URL: parts[1],
		IVBase64URL:           parts[2],
		CiphertextBase64URL:   parts[3],
		AuthTagBase64URL:      parts[4],
	}
	// JWE has no "signature" — the auth tag plays that role,
	// but it's encrypted-key-dependent. We don't claim a
	// signature.
	t.Security = buildSecurityFlags(t)
	return t, nil
}

func enrichHeader(t *Token) {
	t.HeaderAlgorithm = strOr(t.Header, "alg")
	t.HeaderAlgFamily = algorithmFamily(t.HeaderAlgorithm)
	t.HeaderType = strOr(t.Header, "typ")
	t.HeaderContentType = strOr(t.Header, "cty")
	t.HeaderKeyID = strOr(t.Header, "kid")
	t.HeaderX5T = strOr(t.Header, "x5t")
	t.HeaderX5TSHA256 = strOr(t.Header, "x5t#S256")
	t.HeaderJKU = strOr(t.Header, "jku")
	if x5c, ok := t.Header["x5c"].([]interface{}); ok {
		t.HeaderX5CCount = len(x5c)
	}
	if crit, ok := t.Header["crit"].([]interface{}); ok {
		for _, c := range crit {
			if s, ok := c.(string); ok {
				t.HeaderCriticalExt = append(t.HeaderCriticalExt, s)
			}
		}
	}
}

func extractClaims(payload map[string]interface{}) *RegisteredClaims {
	if payload == nil {
		return nil
	}
	c := &RegisteredClaims{
		Issuer:  strOr(payload, "iss"),
		Subject: strOr(payload, "sub"),
		JWTID:   strOr(payload, "jti"),
	}
	// Audience: per RFC 7519 §4.1.3 may be a single string or
	// an array of strings.
	switch v := payload["aud"].(type) {
	case string:
		c.Audience = []string{v}
	case []interface{}:
		for _, e := range v {
			if s, ok := e.(string); ok {
				c.Audience = append(c.Audience, s)
			}
		}
	}
	if v, ok := numericClaim(payload, "exp"); ok {
		c.ExpiresAt = v
		c.ExpiresAtRFC3339 = time.Unix(v, 0).UTC().Format(time.RFC3339)
	}
	if v, ok := numericClaim(payload, "nbf"); ok {
		c.NotBefore = v
		c.NotBeforeRFC3339 = time.Unix(v, 0).UTC().Format(time.RFC3339)
	}
	if v, ok := numericClaim(payload, "iat"); ok {
		c.IssuedAt = v
		c.IssuedAtRFC3339 = time.Unix(v, 0).UTC().Format(time.RFC3339)
	}
	// If none of the registered claims were set, return nil so
	// the field is omitted from JSON output.
	if c.Issuer == "" && c.Subject == "" && c.JWTID == "" &&
		len(c.Audience) == 0 && c.ExpiresAt == 0 &&
		c.NotBefore == 0 && c.IssuedAt == 0 {
		return nil
	}
	return c
}

func buildSecurityFlags(t *Token) *SecurityFlags {
	f := &SecurityFlags{
		AlgNone:          strings.EqualFold(t.HeaderAlgorithm, "none"),
		SignatureMissing: t.Format == "JWS (Compact Serialization)" && !t.SignaturePresent,
	}
	if t.Claims == nil {
		return f
	}
	now := time.Now().UTC()
	if t.Claims.ExpiresAt > 0 {
		exp := time.Unix(t.Claims.ExpiresAt, 0).UTC()
		if now.After(exp) {
			f.Expired = true
			f.HoursSinceExpired = int(now.Sub(exp).Hours())
		} else {
			f.HoursUntilExpiry = int(exp.Sub(now).Hours())
		}
	}
	if t.Claims.NotBefore > 0 {
		nbf := time.Unix(t.Claims.NotBefore, 0).UTC()
		if now.Before(nbf) {
			f.NotYetValid = true
		}
	}
	return f
}

// algorithmFamily classifies the `alg` value into the family
// it belongs to. Per RFC 7518 §3.
func algorithmFamily(alg string) string {
	switch {
	case alg == "":
		return ""
	case strings.EqualFold(alg, "none"):
		return "none (UNSAFE - no signature)"
	// JWE key-management algorithms must match before the
	// generic "RS"/"ES"/"A" prefix tests below, since e.g.
	// "RSA-OAEP" starts with "RS" but is not RSA PKCS#1.
	case strings.Contains(alg, "RSA-OAEP"):
		return "RSA-OAEP (JWE key wrap)"
	case strings.EqualFold(alg, "RSA1_5"):
		return "RSA PKCS#1 v1.5 (JWE key wrap)"
	case strings.Contains(alg, "ECDH-ES"):
		return "ECDH-ES (JWE key agreement)"
	case strings.EqualFold(alg, "dir"):
		return "Direct (JWE shared key)"
	case strings.HasPrefix(alg, "HS"):
		return "HMAC (symmetric)"
	case strings.HasPrefix(alg, "RS"):
		return "RSA PKCS#1 v1.5"
	case strings.HasPrefix(alg, "PS"):
		return "RSA-PSS"
	case strings.HasPrefix(alg, "ES"):
		return "ECDSA"
	case strings.EqualFold(alg, "EdDSA"):
		return "EdDSA (Ed25519 / Ed448)"
	case strings.HasPrefix(alg, "A") && strings.Contains(alg, "GCMKW"):
		return "AES-GCM Key Wrap (JWE)"
	case strings.HasPrefix(alg, "A") && strings.Contains(alg, "KW"):
		return "AES Key Wrap (JWE)"
	case strings.HasPrefix(alg, "A") && strings.Contains(alg, "GCM"):
		return "AES-GCM (JWE content)"
	case strings.HasPrefix(alg, "A") && strings.Contains(alg, "CBC"):
		return "AES-CBC (JWE content)"
	case strings.HasPrefix(alg, "PBES2"):
		return "PBES2 (password-based JWE key wrap)"
	}
	return "unknown / vendor-specific"
}

// decodeBase64URL handles both padded and unpadded inputs.
func decodeBase64URL(s string) ([]byte, error) {
	// Add padding to multiple-of-4 if missing.
	if pad := len(s) % 4; pad != 0 {
		s += strings.Repeat("=", 4-pad)
	}
	return base64.URLEncoding.DecodeString(s)
}

// strOr extracts a string field from a JSON-decoded map.
// Missing or non-string values become "".
func strOr(m map[string]interface{}, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// numericClaim extracts a numeric timestamp claim. JSON
// numbers unmarshal as float64; we cap-cast to int64.
func numericClaim(m map[string]interface{}, key string) (int64, bool) {
	v, ok := m[key]
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}
