// SPDX-License-Identifier: AGPL-3.0-or-later

package otpmigration

import (
	"encoding/base64"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// --- a minimal MigrationPayload encoder, used to build test vectors with the
// authoritative protowire wire format (the inverse of the decoder under test).

func encOtpParameters(secret []byte, name, issuer string, algo, digits, typ, counter uint64) []byte {
	var b []byte
	b = protowire.AppendTag(b, opSecret, protowire.BytesType)
	b = protowire.AppendBytes(b, secret)
	b = protowire.AppendTag(b, opName, protowire.BytesType)
	b = protowire.AppendString(b, name)
	if issuer != "" {
		b = protowire.AppendTag(b, opIssuer, protowire.BytesType)
		b = protowire.AppendString(b, issuer)
	}
	b = protowire.AppendTag(b, opAlgorithm, protowire.VarintType)
	b = protowire.AppendVarint(b, algo)
	b = protowire.AppendTag(b, opDigits, protowire.VarintType)
	b = protowire.AppendVarint(b, digits)
	b = protowire.AppendTag(b, opType, protowire.VarintType)
	b = protowire.AppendVarint(b, typ)
	if counter != 0 {
		b = protowire.AppendTag(b, opCounter, protowire.VarintType)
		b = protowire.AppendVarint(b, counter)
	}
	return b
}

func encPayload(version int, params ...[]byte) string {
	var b []byte
	for _, p := range params {
		b = protowire.AppendTag(b, fieldOtpParameters, protowire.BytesType)
		b = protowire.AppendBytes(b, p)
	}
	b = protowire.AppendTag(b, fieldVersion, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(version))
	return base64.StdEncoding.EncodeToString(b)
}

// helloSecret is "Hello!" + 0xDEADBEEF — the canonical otpauth-migration
// example secret, whose RFC 4648 base32 (no padding) is the well-known
// JBSWY3DPEHPK3PXP. That base32 value is hand-verifiable bit-for-bit and is the
// external anchor pinning the decoder's secret handling.
var helloSecret = []byte{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xef}

const helloSecretB32 = "JBSWY3DPEHPK3PXP"

// TestDecodeCanonicalAccount builds the canonical single-account payload and
// confirms every field decodes, with the secret cross-checked against the
// independently-computed base32.
func TestDecodeCanonicalAccount(t *testing.T) {
	data := encPayload(1, encOtpParameters(helloSecret, "Test:alice@google.com", "Example", 1, 1, 2, 0))
	uri := "otpauth-migration://offline?data=" + data

	r, err := Decode(uri)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Count != 1 || len(r.Accounts) != 1 {
		t.Fatalf("Count = %d; want 1", r.Count)
	}
	a := r.Accounts[0]
	if a.Secret != helloSecretB32 {
		t.Errorf("Secret = %q; want %q (base32 of Hello!+0xDEADBEEF)", a.Secret, helloSecretB32)
	}
	if a.Issuer != "Example" {
		t.Errorf("Issuer = %q; want Example", a.Issuer)
	}
	if a.Name != "Test:alice@google.com" {
		t.Errorf("Name = %q; want Test:alice@google.com", a.Name)
	}
	if a.Algorithm != "SHA1" {
		t.Errorf("Algorithm = %q; want SHA1", a.Algorithm)
	}
	if a.Digits != 6 {
		t.Errorf("Digits = %d; want 6", a.Digits)
	}
	if a.Type != "totp" {
		t.Errorf("Type = %q; want totp", a.Type)
	}
	// The reconstructed otpauth URI must carry the secret + issuer so it pipes
	// straight into totp_generate.
	if !strings.HasPrefix(a.OtpauthURI, "otpauth://totp/") ||
		!strings.Contains(a.OtpauthURI, "secret="+helloSecretB32) ||
		!strings.Contains(a.OtpauthURI, "issuer=Example") {
		t.Errorf("OtpauthURI = %q; want a totp URI carrying the secret + issuer", a.OtpauthURI)
	}
}

// TestDecodeBareDataAndURLBase64 confirms the bare base64 (not wrapped in a
// URI) and the URL-base64 alphabet are both accepted.
func TestDecodeBareDataAndURLBase64(t *testing.T) {
	std := encPayload(1, encOtpParameters(helloSecret, "a", "I", 2, 2, 1, 7))
	if _, err := Decode(std); err != nil {
		t.Errorf("bare std base64: %v", err)
	}
	// Re-encode the same bytes as URL base64 (no padding) and confirm it decodes.
	raw, _ := base64.StdEncoding.DecodeString(std)
	if _, err := Decode(base64.RawURLEncoding.EncodeToString(raw)); err != nil {
		t.Errorf("bare url base64: %v", err)
	}
}

// TestDecodeMultiAccountAndHOTP covers several accounts, an 8-digit SHA256
// TOTP, and an HOTP entry with a counter.
func TestDecodeMultiAccountAndHOTP(t *testing.T) {
	data := encPayload(1,
		encOtpParameters(helloSecret, "alice", "GitHub", 1, 1, 2, 0), // SHA1/6/TOTP
		encOtpParameters(helloSecret, "bob", "AWS", 2, 2, 2, 0),      // SHA256/8/TOTP
		encOtpParameters(helloSecret, "carol", "Bank", 1, 1, 1, 42),  // HOTP, counter 42
	)
	r, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Count != 3 {
		t.Fatalf("Count = %d; want 3", r.Count)
	}
	if r.Accounts[1].Algorithm != "SHA256" || r.Accounts[1].Digits != 8 {
		t.Errorf("account 2 = %s/%d; want SHA256/8", r.Accounts[1].Algorithm, r.Accounts[1].Digits)
	}
	hotp := r.Accounts[2]
	if hotp.Type != "hotp" || hotp.Counter != 42 {
		t.Errorf("account 3 = %s counter %d; want hotp counter 42", hotp.Type, hotp.Counter)
	}
	if !strings.Contains(hotp.OtpauthURI, "counter=42") {
		t.Errorf("HOTP OtpauthURI = %q; want counter=42", hotp.OtpauthURI)
	}
}

// TestUnknownEnumSurfacedRaw confirms an out-of-range algorithm enum is
// surfaced rather than silently mapped to a real algorithm.
func TestUnknownEnumSurfacedRaw(t *testing.T) {
	data := encPayload(1, encOtpParameters(helloSecret, "x", "Y", 9, 1, 2, 0))
	r, err := Decode(data)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.HasPrefix(r.Accounts[0].Algorithm, "UNSPECIFIED(9)") {
		t.Errorf("Algorithm = %q; want UNSPECIFIED(9)", r.Accounts[0].Algorithm)
	}
}

func TestDecodeRejects(t *testing.T) {
	cases := map[string]string{
		"empty":              "",
		"single otpauth URI": "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP",
		"uri without data":   "otpauth-migration://offline?foo=bar",
		"not base64":         "!!!! not base64 !!!!",
		"empty payload":      base64.StdEncoding.EncodeToString(nil),
		"no accounts":        base64.StdEncoding.EncodeToString([]byte{0x10, 0x01}), // only version=1
	}
	for name, in := range cases {
		if _, err := Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}
