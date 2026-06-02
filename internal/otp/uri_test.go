// SPDX-License-Identifier: AGPL-3.0-or-later

package otp

import (
	"testing"
	"time"
)

// rfcSeedB32 is the RFC 4226/6238 ASCII seed "12345678901234567890" in base32
// (the form an otpauth:// secret parameter carries).
const rfcSeedB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestParseURI_Fields(t *testing.T) {
	const uri = "otpauth://totp/ACME%20Co:alice@acme.com?secret=" + rfcSeedB32 +
		"&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60"
	p, err := ParseURI(uri)
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "totp" {
		t.Errorf("Type = %q, want totp", p.Type)
	}
	if p.Secret != rfcSeedB32 {
		t.Errorf("Secret = %q, want %q", p.Secret, rfcSeedB32)
	}
	if p.Algorithm != "SHA256" {
		t.Errorf("Algorithm = %q, want SHA256", p.Algorithm)
	}
	if p.Digits != 8 {
		t.Errorf("Digits = %d, want 8", p.Digits)
	}
	if p.Period != 60 {
		t.Errorf("Period = %d, want 60", p.Period)
	}
	if p.Issuer != "ACME Co" {
		t.Errorf("Issuer = %q, want 'ACME Co'", p.Issuer)
	}
	if p.Account != "alice@acme.com" {
		t.Errorf("Account = %q, want alice@acme.com", p.Account)
	}
}

// TestParseURI_Defaults verifies absent parameters take the spec defaults.
func TestParseURI_Defaults(t *testing.T) {
	p, err := ParseURI("otpauth://totp/Example?secret=" + rfcSeedB32)
	if err != nil {
		t.Fatal(err)
	}
	if p.Algorithm != "SHA1" || p.Digits != 6 || p.Period != 30 {
		t.Errorf("defaults wrong: %+v", p)
	}
	if p.HasCounter {
		t.Error("totp URI must not report a counter")
	}
}

// TestParseURI_RFCVector is the correctness gate: a URI carrying the RFC seed
// with digits=8 must, through the parsed fields, reproduce the RFC 6238
// Appendix B SHA-1 vector (T=59 -> 94287082). This proves the parser feeds the
// generator the right secret + parameters.
func TestParseURI_RFCVector(t *testing.T) {
	p, err := ParseURI("otpauth://totp/RFC?secret=" + rfcSeedB32 + "&digits=8")
	if err != nil {
		t.Fatal(err)
	}
	key, err := DecodeSecret(p.Secret)
	if err != nil {
		t.Fatal(err)
	}
	h, err := HashFor(p.Algorithm)
	if err != nil {
		t.Fatal(err)
	}
	if got := TOTP(key, time.Unix(59, 0), p.Period, p.Digits, h); got != "94287082" {
		t.Errorf("TOTP from parsed URI = %s, want 94287082", got)
	}
}

func TestParseURI_HOTPCounter(t *testing.T) {
	p, err := ParseURI("otpauth://hotp/Example?secret=" + rfcSeedB32 + "&counter=5")
	if err != nil {
		t.Fatal(err)
	}
	if p.Type != "hotp" || !p.HasCounter || p.Counter != 5 {
		t.Errorf("hotp counter parse wrong: %+v", p)
	}
}

func TestParseURI_Errors(t *testing.T) {
	cases := map[string]string{
		"wrong scheme":    "https://totp/x?secret=" + rfcSeedB32,
		"bad type":        "otpauth://yotp/x?secret=" + rfcSeedB32,
		"missing secret":  "otpauth://totp/x?issuer=ACME",
		"bad digits":      "otpauth://totp/x?secret=" + rfcSeedB32 + "&digits=9",
		"bad period":      "otpauth://totp/x?secret=" + rfcSeedB32 + "&period=0",
		"bad algorithm":   "otpauth://totp/x?secret=" + rfcSeedB32 + "&algorithm=MD5",
		"bad counter":     "otpauth://hotp/x?secret=" + rfcSeedB32 + "&counter=abc",
		"hotp no counter": "otpauth://hotp/x?secret=" + rfcSeedB32,
	}
	for name, uri := range cases {
		if _, err := ParseURI(uri); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
