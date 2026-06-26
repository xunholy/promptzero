// SPDX-License-Identifier: AGPL-3.0-or-later

package cose

import (
	"encoding/hex"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test hex %q: %v", s, err)
	}
	return b
}

// TestDecodeKey_EC2_ES256 is the common WebAuthn credential key shape:
// {1:2(EC2), 3:-7(ES256), -1:1(P-256), -2:x, -3:y}.
func TestDecodeKey_EC2_ES256(t *testing.T) {
	x := strings.Repeat("11", 32)
	y := strings.Repeat("22", 32)
	raw := mustHex(t, "a5"+"0102"+"0326"+"2001"+"215820"+x+"225820"+y)
	k, err := DecodeKey(raw)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if k.KeyType != "EC2" || k.Algorithm != "ES256" || k.Curve != "P-256" {
		t.Errorf("got kty=%s alg=%s crv=%s; want EC2/ES256/P-256", k.KeyType, k.Algorithm, k.Curve)
	}
	if k.XHex != x || k.YHex != y {
		t.Errorf("coordinates: x=%q y=%q", k.XHex, k.YHex)
	}
	if k.HasPrivateKey {
		t.Error("HasPrivateKey should be false for a public key")
	}
}

// TestDecodeKey_OKP_Ed25519: {1:1(OKP), 3:-8(EdDSA), -1:6(Ed25519), -2:x}.
func TestDecodeKey_OKP_Ed25519(t *testing.T) {
	x := strings.Repeat("33", 32)
	raw := mustHex(t, "a4"+"0101"+"0327"+"2006"+"215820"+x)
	k, err := DecodeKey(raw)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if k.KeyType != "OKP" || k.Algorithm != "EdDSA" || k.Curve != "Ed25519" || k.XHex != x {
		t.Errorf("got %+v", k)
	}
	if k.YHex != "" {
		t.Errorf("OKP must not have a y coordinate, got %q", k.YHex)
	}
}

// TestDecodeKey_RSA: {1:3(RSA), 3:-257(RS256), -1:n, -2:e}.
func TestDecodeKey_RSA(t *testing.T) {
	raw := mustHex(t, "a4"+"0103"+"03390100"+"2043010203"+"2143010001")
	k, err := DecodeKey(raw)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if k.KeyType != "RSA" || k.Algorithm != "RS256" {
		t.Errorf("got kty=%s alg=%s; want RSA/RS256", k.KeyType, k.Algorithm)
	}
	if k.ModulusHex != "010203" || k.ExponentHex != "010001" {
		t.Errorf("n=%q e=%q", k.ModulusHex, k.ExponentHex)
	}
}

// TestDecodeKey_PrivateFlag: an EC2 key with a d (-4) component is flagged.
func TestDecodeKey_PrivateFlag(t *testing.T) {
	x := strings.Repeat("11", 32)
	y := strings.Repeat("22", 32)
	d := strings.Repeat("44", 32)
	raw := mustHex(t, "a6"+"0102"+"0326"+"2001"+"215820"+x+"225820"+y+"235820"+d)
	k, err := DecodeKey(raw)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if !k.HasPrivateKey {
		t.Error("HasPrivateKey should be true when d (-4) is present")
	}
}

// TestDecodeKey_UnknownAlg: an unrecognised alg falls back to unknown(N),
// never a wrong name.
func TestDecodeKey_UnknownAlg(t *testing.T) {
	raw := mustHex(t, "a2"+"0102"+"033863") // kty EC2, alg -100
	k, err := DecodeKey(raw)
	if err != nil {
		t.Fatalf("DecodeKey: %v", err)
	}
	if k.Algorithm != "unknown(-100)" {
		t.Errorf("alg = %q, want unknown(-100)", k.Algorithm)
	}
}

func TestDecodeKey_Errors(t *testing.T) {
	cases := map[string]string{
		"not a map":         "01",       // uint, not a map
		"missing kty":       "a10326",   // {3:-7} only
		"non-integer label": "a1616102", // {"a":2}
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeKey(mustHex(t, h)); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}
