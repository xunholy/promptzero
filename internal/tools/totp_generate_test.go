// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// rfcSeedB32 is the RFC 4226/6238 ASCII seed "12345678901234567890" in base32.
const rfcSeedB32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func runTOTP(t *testing.T, args map[string]any) map[string]any {
	t.Helper()
	out, err := totpGenerateHandler(context.Background(), nil, args)
	if err != nil {
		t.Fatalf("totpGenerateHandler: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, out)
	}
	return m
}

// TestTOTPHandler_RFCVector locks in the base32-secret path against the RFC 6238
// Appendix B vector (T=59, SHA1, 8 digits, 30s -> 94287082).
func TestTOTPHandler_RFCVector(t *testing.T) {
	m := runTOTP(t, map[string]any{
		"secret": rfcSeedB32, "digits": 8, "timestamp": 59,
	})
	if m["code"] != "94287082" {
		t.Errorf("code = %v, want 94287082", m["code"])
	}
}

// TestTOTPHandler_OtpauthURI is the integration gate: the same RFC vector reached
// through an otpauth:// URI (digits carried by the URI, not the args) must match.
func TestTOTPHandler_OtpauthURI(t *testing.T) {
	m := runTOTP(t, map[string]any{
		"secret":    "otpauth://totp/ACME:rfc@acme.com?secret=" + rfcSeedB32 + "&digits=8&issuer=ACME",
		"timestamp": 59,
	})
	if m["code"] != "94287082" {
		t.Errorf("code = %v, want 94287082", m["code"])
	}
	if m["digits"].(float64) != 8 {
		t.Errorf("digits from URI = %v, want 8", m["digits"])
	}
	if m["source"] != "otpauth_uri" || m["issuer"] != "ACME" || m["account"] != "rfc@acme.com" {
		t.Errorf("URI context wrong: source=%v issuer=%v account=%v", m["source"], m["issuer"], m["account"])
	}
}

// TestTOTPHandler_URIOverridesDefaults proves the correctness win: a SHA256
// enrolment via URI yields a different code than the same secret with the tool's
// SHA1 default — i.e. the URI's algorithm is actually applied.
func TestTOTPHandler_URIOverridesDefaults(t *testing.T) {
	sha1Code := runTOTP(t, map[string]any{"secret": rfcSeedB32, "timestamp": 59})["code"]
	sha256Code := runTOTP(t, map[string]any{
		"secret":    "otpauth://totp/x?secret=" + rfcSeedB32 + "&algorithm=SHA256",
		"timestamp": 59,
	})["code"]
	if sha1Code == sha256Code {
		t.Errorf("SHA256 URI should differ from SHA1 default; both = %v", sha1Code)
	}
}

// TestTOTPHandler_OtpauthHOTP exercises the hotp URI path (counter from the URI).
func TestTOTPHandler_OtpauthHOTP(t *testing.T) {
	m := runTOTP(t, map[string]any{
		"secret": "otpauth://hotp/x?secret=" + rfcSeedB32 + "&counter=0",
	})
	if m["mode"] != "hotp" || m["code"] != "755224" { // RFC 4226 counter 0
		t.Errorf("hotp URI: mode=%v code=%v, want hotp/755224", m["mode"], m["code"])
	}
}

func TestTOTPHandler_BadURI(t *testing.T) {
	if _, err := totpGenerateHandler(context.Background(), nil, map[string]any{
		"secret": "otpauth://totp/x?digits=8", // missing secret
	}); err == nil || !strings.Contains(err.Error(), "secret") {
		t.Errorf("expected missing-secret error, got %v", err)
	}
}
