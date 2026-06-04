// SPDX-License-Identifier: AGPL-3.0-or-later

package x509decode

import "testing"

// TestJA4XHashAnchors verifies the hash12 + OID-hex format against three
// recurring RDN hashes from the FoxIO browsers-x509 snapshot.
func TestJA4XHashAnchors(t *testing.T) {
	cases := map[string]string{
		"550406,55040a,550403":               "a373a9f83c6b", // C,O,CN
		"550406,55040a,55040b,550403":        "7d5dbb3783b4", // C,O,OU,CN
		"550406,550408,550407,55040a,550403": "2bab15409345", // C,ST,L,O,CN
	}
	for in, want := range cases {
		if got := ja4xHash12(in); got != want {
			t.Errorf("ja4xHash12(%q) = %q, want %q", in, got, want)
		}
	}
	if ja4xHash12("") != "000000000000" {
		t.Errorf("empty ja4xHash12 = %q, want twelve zeros", ja4xHash12(""))
	}
}

// A self-signed P-256 cert with subject/issuer C,O,CN and the standard
// SKI/AKI/BasicConstraints extensions. Expected JA4X computed from the
// FoxIO-verified algorithm: C,O,CN -> a373a9f83c6b (issuer + subject),
// SKI(2.5.29.14)+AKI(2.5.29.35)+BasicConstraints(2.5.29.19) -> 795797892f9c.
const ja4xCert = `-----BEGIN CERTIFICATE-----
MIIBqTCCAU+gAwIBAgIUGXAHC44VPIxUtkdi/KpIFUlQnCkwCgYIKoZIzj0EAwIw
KjELMAkGA1UEBhMCVVMxDDAKBgNVBAoMA29yZzENMAsGA1UEAwwEdGVzdDAeFw0y
NjA2MDQyMDA4MjZaFw0zNjA2MDEyMDA4MjZaMCoxCzAJBgNVBAYTAlVTMQwwCgYD
VQQKDANvcmcxDTALBgNVBAMMBHRlc3QwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AATmWrDA/T98kiQQxnpreS3R1UivaDMdN3qRz+0TAuwVEUYCBdTFgN2n3aVYdH1p
kTKIAv6buizZx5oxg9ZjQsRio1MwUTAdBgNVHQ4EFgQU0B2ScoydAqopMnj8TRqU
KHUshr8wHwYDVR0jBBgwFoAU0B2ScoydAqopMnj8TRqUKHUshr8wDwYDVR0TAQH/
BAUwAwEB/zAKBggqhkjOPQQDAgNIADBFAiB3a/bkJ7XZOI/qFo16IEkSsdsMRs/w
vBBhXZXHog/IeAIhAMTYi07J0UMB7Ekme03l+Sc5+LrGqEmv04tvP90HY9T9
-----END CERTIFICATE-----`

func TestJA4XEndToEnd(t *testing.T) {
	c, err := Decode(ja4xCert)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	const want = "a373a9f83c6b_a373a9f83c6b_795797892f9c"
	if c.JA4X != want {
		t.Errorf("JA4X = %q, want %q", c.JA4X, want)
	}
}
