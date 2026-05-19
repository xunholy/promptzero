package jwtdecode

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestDecode_HS256_Standard pins the canonical jwt.io HS256
// example with payload {sub, name, iat}. This is the most-
// quoted JWT test vector on the internet.
func TestDecode_HS256_Standard(t *testing.T) {
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "JWS (Compact Serialization)" {
		t.Errorf("Format = %q", got.Format)
	}
	if got.HeaderAlgorithm != "HS256" {
		t.Errorf("HeaderAlgorithm = %q; want HS256", got.HeaderAlgorithm)
	}
	if got.HeaderAlgFamily != "HMAC (symmetric)" {
		t.Errorf("HeaderAlgFamily = %q", got.HeaderAlgFamily)
	}
	if got.HeaderType != "JWT" {
		t.Errorf("HeaderType = %q", got.HeaderType)
	}
	if got.Claims == nil {
		t.Fatal("Claims nil")
	}
	if got.Claims.Subject != "1234567890" {
		t.Errorf("Subject = %q", got.Claims.Subject)
	}
	if got.Claims.IssuedAt != 1516239022 {
		t.Errorf("IssuedAt = %d; want 1516239022", got.Claims.IssuedAt)
	}
	if got.Payload["name"] != "John Doe" {
		t.Errorf("name claim = %v; want 'John Doe'", got.Payload["name"])
	}
	if !got.SignaturePresent {
		t.Error("SignaturePresent = false; want true")
	}
	if got.SignatureLength != 32 {
		t.Errorf("SignatureLength = %d; want 32 (HMAC-SHA256)", got.SignatureLength)
	}
	if got.Security.AlgNone {
		t.Error("AlgNone = true; want false")
	}
}

// TestDecode_AlgNone_Detected verifies the alg=none danger
// flag.
func TestDecode_AlgNone_Detected(t *testing.T) {
	token := buildJWT(t,
		map[string]interface{}{"alg": "none", "typ": "JWT"},
		map[string]interface{}{"sub": "admin"},
		"",
	)
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Security.AlgNone {
		t.Error("Security.AlgNone = false; want true (alg=none vulnerability)")
	}
	if !strings.Contains(got.HeaderAlgFamily, "UNSAFE") {
		t.Errorf("HeaderAlgFamily = %q; want UNSAFE label", got.HeaderAlgFamily)
	}
	if !got.Security.SignatureMissing {
		t.Error("SignatureMissing = false; want true (empty signature)")
	}
}

// TestDecode_Expired sets exp in the past and verifies the
// expired flag.
func TestDecode_Expired(t *testing.T) {
	exp := time.Now().Add(-2 * time.Hour).Unix()
	token := buildJWT(t,
		map[string]interface{}{"alg": "HS256", "typ": "JWT"},
		map[string]interface{}{"sub": "alice", "exp": exp},
		"signature-bytes",
	)
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Security.Expired {
		t.Error("Expired = false; want true")
	}
	if got.Security.HoursSinceExpired < 1 {
		t.Errorf("HoursSinceExpired = %d; want >= 1", got.Security.HoursSinceExpired)
	}
}

// TestDecode_NotYetValid sets nbf in the future.
func TestDecode_NotYetValid(t *testing.T) {
	nbf := time.Now().Add(2 * time.Hour).Unix()
	token := buildJWT(t,
		map[string]interface{}{"alg": "RS256"},
		map[string]interface{}{"sub": "bob", "nbf": nbf},
		"sig",
	)
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.Security.NotYetValid {
		t.Error("NotYetValid = false; want true")
	}
}

// TestDecode_AudienceArray exercises the multi-audience form
// (RFC 7519 §4.1.3 allows audience to be a single string or
// an array).
func TestDecode_AudienceArray(t *testing.T) {
	token := buildJWT(t,
		map[string]interface{}{"alg": "ES256"},
		map[string]interface{}{
			"aud": []string{"api.example.com", "admin.example.com"},
		},
		"sig",
	)
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Claims.Audience) != 2 {
		t.Fatalf("Audience count = %d; want 2", len(got.Claims.Audience))
	}
	if got.Claims.Audience[0] != "api.example.com" {
		t.Errorf("Audience[0] = %q", got.Claims.Audience[0])
	}
}

// TestDecode_AlgorithmFamilies pins the family classification
// across the major algs.
func TestDecode_AlgorithmFamilies(t *testing.T) {
	cases := map[string]string{
		"":      "",
		"HS256": "HMAC (symmetric)",
		"HS384": "HMAC (symmetric)",
		"HS512": "HMAC (symmetric)",
		"RS256": "RSA PKCS#1 v1.5",
		"RS384": "RSA PKCS#1 v1.5",
		"RS512": "RSA PKCS#1 v1.5",
		"PS256": "RSA-PSS",
		"PS384": "RSA-PSS",
		"PS512": "RSA-PSS",
		"ES256": "ECDSA",
		"ES384": "ECDSA",
		"ES512": "ECDSA",
		"EdDSA": "EdDSA (Ed25519 / Ed448)",
		"none":  "none (UNSAFE - no signature)",
	}
	for alg, want := range cases {
		if got := algorithmFamily(alg); got != want {
			t.Errorf("algorithmFamily(%q) = %q; want %q", alg, got, want)
		}
	}
}

// TestDecode_BearerPrefix tolerates a leading 'Bearer ' prefix.
func TestDecode_BearerPrefix(t *testing.T) {
	token := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
		"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Claims.Subject != "1234567890" {
		t.Errorf("Subject = %q", got.Claims.Subject)
	}
}

// TestDecode_HeaderFields pins kid, x5t, jku, x5c-count.
func TestDecode_HeaderFields(t *testing.T) {
	token := buildJWT(t,
		map[string]interface{}{
			"alg":      "RS256",
			"typ":      "JWT",
			"kid":      "test-key-1",
			"x5t":      "abc123",
			"x5t#S256": "def456",
			"jku":      "https://example.com/keys.json",
			"x5c":      []interface{}{"cert1", "cert2", "cert3"},
		},
		map[string]interface{}{"sub": "x"},
		"sig",
	)
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HeaderKeyID != "test-key-1" {
		t.Errorf("HeaderKeyID = %q", got.HeaderKeyID)
	}
	if got.HeaderX5T != "abc123" {
		t.Errorf("HeaderX5T = %q", got.HeaderX5T)
	}
	if got.HeaderX5TSHA256 != "def456" {
		t.Errorf("HeaderX5TSHA256 = %q", got.HeaderX5TSHA256)
	}
	if got.HeaderJKU != "https://example.com/keys.json" {
		t.Errorf("HeaderJKU = %q", got.HeaderJKU)
	}
	if got.HeaderX5CCount != 3 {
		t.Errorf("HeaderX5CCount = %d; want 3", got.HeaderX5CCount)
	}
}

// TestDecode_JWE_FiveSegments labels JWE tokens and surfaces
// the four ciphertext segments without decrypting.
func TestDecode_JWE_FiveSegments(t *testing.T) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RSA-OAEP","enc":"A256GCM","kid":"jwe-key"}`))
	jwe := header + ".encrypted_key.iv.ciphertext.tag"
	got, err := Decode(jwe)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Format != "JWE (Compact Serialization)" {
		t.Errorf("Format = %q", got.Format)
	}
	if got.HeaderAlgorithm != "RSA-OAEP" {
		t.Errorf("HeaderAlgorithm = %q", got.HeaderAlgorithm)
	}
	if got.HeaderAlgFamily != "RSA-OAEP (JWE key wrap)" {
		t.Errorf("HeaderAlgFamily = %q", got.HeaderAlgFamily)
	}
	if got.JWESegments == nil {
		t.Fatal("JWESegments nil")
	}
	if got.JWESegments.CiphertextBase64URL != "ciphertext" {
		t.Errorf("CiphertextBase64URL = %q", got.JWESegments.CiphertextBase64URL)
	}
}

// TestDecode_BadInput rejects malformed tokens.
func TestDecode_BadInput(t *testing.T) {
	cases := []string{
		"",
		"notajwt",
		"only.two",
		"one.two.three.four", // 4 segments (invalid)
	}
	for _, c := range cases {
		if _, err := Decode(c); err == nil {
			t.Errorf("input %q: want error", c)
		}
	}
}

// TestDecode_BadBase64 rejects garbage segments.
func TestDecode_BadBase64(t *testing.T) {
	if _, err := Decode("!!!.!!!.!!!"); err == nil {
		t.Error("garbage base64: want error")
	}
}

// TestDecode_BadJSON rejects segments that are valid base64
// but not JSON.
func TestDecode_BadJSON(t *testing.T) {
	// Base64url for "notjson"
	hdr := base64.RawURLEncoding.EncodeToString([]byte("notjson"))
	if _, err := Decode(hdr + "." + hdr + "." + hdr); err == nil {
		t.Error("invalid JSON header: want error")
	}
}

// TestDecode_UnpaddedBase64URL handles the unpadded URL-safe
// base64 encoding standard JWTs use.
func TestDecode_UnpaddedBase64URL(t *testing.T) {
	// Construct a token where each segment, when base64url-
	// encoded, would naturally need padding. The decoder must
	// add it back.
	header := map[string]interface{}{"alg": "HS256"}
	hdrBytes, _ := json.Marshal(header)
	payload := map[string]interface{}{"a": "b"} // short payload
	plBytes, _ := json.Marshal(payload)
	hdrEnc := base64.RawURLEncoding.EncodeToString(hdrBytes)
	plEnc := base64.RawURLEncoding.EncodeToString(plBytes)
	sigEnc := base64.RawURLEncoding.EncodeToString([]byte("xyz"))
	tok := hdrEnc + "." + plEnc + "." + sigEnc
	got, err := Decode(tok)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.HeaderAlgorithm != "HS256" {
		t.Errorf("HeaderAlgorithm = %q", got.HeaderAlgorithm)
	}
}

// TestDecodeBase64URL_PaddingAdded exercises the helper.
func TestDecodeBase64URL_PaddingAdded(t *testing.T) {
	// "Man" base64url = "TWFu" (no padding needed)
	got, err := decodeBase64URL("TWFu")
	if err != nil || string(got) != "Man" {
		t.Errorf("decodeBase64URL('TWFu') = %q (err %v)", got, err)
	}
	// "M" base64url = "TQ" (would normally need 2 '=' padding)
	got, err = decodeBase64URL("TQ")
	if err != nil || string(got) != "M" {
		t.Errorf("decodeBase64URL('TQ') = %q (err %v)", got, err)
	}
}

// TestDecode_CriticalExtensions surfaces the crit list.
func TestDecode_CriticalExtensions(t *testing.T) {
	token := buildJWT(t,
		map[string]interface{}{
			"alg":  "RS256",
			"crit": []interface{}{"exp", "custom-ext"},
		},
		map[string]interface{}{"sub": "x"},
		"sig",
	)
	got, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.HeaderCriticalExt) != 2 {
		t.Fatalf("HeaderCriticalExt count = %d", len(got.HeaderCriticalExt))
	}
	if got.HeaderCriticalExt[0] != "exp" {
		t.Errorf("HeaderCriticalExt[0] = %q", got.HeaderCriticalExt[0])
	}
}

// buildJWT is a test helper that constructs a JWT compact-
// serialization string from arbitrary header / payload maps
// + a literal signature string.
func buildJWT(t *testing.T, header, payload map[string]interface{}, sig string) string {
	t.Helper()
	hdrBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	plBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return fmt.Sprintf("%s.%s.%s",
		base64.RawURLEncoding.EncodeToString(hdrBytes),
		base64.RawURLEncoding.EncodeToString(plBytes),
		base64.RawURLEncoding.EncodeToString([]byte(sig)),
	)
}
