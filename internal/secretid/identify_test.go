// SPDX-License-Identifier: AGPL-3.0-or-later

package secretid_test

import (
	"hash/crc32"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/secretid"
)

func TestIdentifyAWSKey(t *testing.T) {
	// Published vector (ASIAY34FZKBOKMUTVV7A → account 609629065308).
	r := secretid.Identify("ASIAY34FZKBOKMUTVV7A")
	if !r.Matched || r.Category != "cloud-aws" || !r.Validated || !r.Valid {
		t.Fatalf("AWS: %+v", r)
	}
	if !strings.Contains(r.Detail, "609629065308") {
		t.Errorf("AWS detail missing account: %q", r.Detail)
	}
}

func TestIdentifyGitHubToken(t *testing.T) {
	// Build the canonical valid token from parts (no contiguous literal).
	const dict = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	entropy := "zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ"
	crc := uint64(crc32.ChecksumIEEE([]byte(entropy)))
	cs := []byte("000000")
	for i := 5; i >= 0; i-- {
		cs[i] = dict[crc%62]
		crc /= 62
	}
	r := secretid.Identify("ghp_" + entropy + string(cs))
	if !r.Matched || r.Category != "vcs" || !r.Validated || !r.Valid {
		t.Fatalf("GitHub: %+v", r)
	}
}

func TestIdentifyJWT(t *testing.T) {
	// header {"alg":"HS256","typ":"JWT"} . payload {"sub":"x"} . sig
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.abc"
	r := secretid.Identify(jwt)
	if !r.Matched || r.Category != "token-jwt" {
		t.Fatalf("JWT: %+v", r)
	}
	if !strings.Contains(r.Detail, "HS256") {
		t.Errorf("JWT detail missing alg: %q", r.Detail)
	}
}

func TestIdentifyAzureSAS(t *testing.T) {
	r := secretid.Identify("?sp=rw&se=2024-01-01T00:00:00Z&sv=2022-11-02&sr=b&sig=abc123")
	if !r.Matched || r.Category != "cloud-azure" {
		t.Fatalf("Azure SAS: %+v", r)
	}
}

func TestIdentifyPEMVariants(t *testing.T) {
	cases := map[string]string{
		"-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END...": "ssh",
		"-----BEGIN RSA PRIVATE KEY-----\nx":                  "ssh",
		"-----BEGIN CERTIFICATE-----\nx":                      "x509",
		"-----BEGIN PGP PUBLIC KEY BLOCK-----\nx":             "pgp",
		"-----BEGIN PUBLIC KEY-----\nx":                       "x509",
	}
	for in, wantCat := range cases {
		r := secretid.Identify(in)
		if !r.Matched || r.Category != wantCat {
			t.Errorf("PEM %q: cat=%q want %q (%+v)", strings.SplitN(in, "\n", 2)[0], r.Category, wantCat, r)
		}
	}
}

func TestIdentifyVendorPrefixes(t *testing.T) {
	cases := map[string]string{
		"xoxb-123-456-abc":   "Slack bot token",
		"glpat-abcdefghij":   "GitLab personal access token",
		"sk-ant-api03-xxxxx": "Anthropic API key",
		"sk-proj-xxxxx":      "OpenAI project API key",
		"sk_live_abcdef":     "Stripe secret live key",
		"pk_test_abcdef":     "Stripe publishable test key",
		"npm_abcdefghij":     "npm access token",
		"AIzaSyAbCdEf":       "Google API key",
		"SG.abcdef.ghijkl":   "SendGrid API key",
	}
	for in, wantType := range cases {
		r := secretid.Identify(in)
		if !r.Matched || r.Type != wantType {
			t.Errorf("vendor %q: type=%q want %q", in, r.Type, wantType)
		}
		if r.Validated {
			t.Errorf("vendor %q: validated=true; prefix matches are format-only", in)
		}
	}
}

func TestIdentifyBIP39(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	r := secretid.Identify(mnemonic)
	if !r.Matched || r.Category != "crypto-wallet" || !r.Validated || !r.Valid {
		t.Fatalf("BIP-39: %+v", r)
	}
	if !strings.Contains(r.Detail, "12 words") {
		t.Errorf("BIP-39 detail: %q", r.Detail)
	}
}

func TestIdentifyDiscordToken(t *testing.T) {
	// base64url("175928847299117063").seg2.hmac — first segment is a user ID.
	seg1 := "MTc1OTI4ODQ3Mjk5MTE3MDYz"
	r := secretid.Identify(seg1 + ".G3xxxx.HmAcSiG")
	if !r.Matched || r.Category != "token-discord" {
		t.Fatalf("Discord: %+v", r)
	}
	if !strings.Contains(r.Detail, "175928847299117063") {
		t.Errorf("Discord detail missing user ID: %q", r.Detail)
	}
	// A JWT must still be classified as JWT, not Discord (header is JSON, not digits).
	if j := secretid.Identify("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig"); j.Category != "token-jwt" {
		t.Errorf("JWT misclassified as %q", j.Category)
	}
}

func TestUnrecognised(t *testing.T) {
	cases := []string{"", "hello world this is just text", "0123456789abcdef0123456789abcdef01234567"}
	for _, in := range cases {
		r := secretid.Identify(in)
		if r.Matched {
			t.Errorf("Identify(%q) matched %q; want unmatched", in, r.Type)
		}
		if in != "" && r.Note == "" {
			t.Errorf("Identify(%q): expected a shape-hint note", in)
		}
	}
}

// TestStripeOrderingNotMisidentified guards the sk- ordering: a Stripe sk_live_
// key must not be swallowed by the sk- OpenAI prefix (underscore vs hyphen).
func TestStripeOrderingNotMisidentified(t *testing.T) {
	if r := secretid.Identify("sk_live_abc"); r.Type != "Stripe secret live key" {
		t.Errorf("sk_live_ misidentified as %q", r.Type)
	}
	if r := secretid.Identify("sk-anything"); !strings.Contains(r.Type, "OpenAI") {
		t.Errorf("sk- = %q; want OpenAI/LLM", r.Type)
	}
}
