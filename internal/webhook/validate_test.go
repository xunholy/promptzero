package webhook

import (
	"strings"
	"testing"
)

// TestValidateSubscription_RejectsLoopback locks the SSRF gate against
// the most common attack target: webhooks pointed at 127.0.0.1.
// Webhook payloads include captured tool inputs/outputs, so a
// loopback-targeted webhook can leak them to a co-resident service.
func TestValidateSubscription_RejectsLoopback(t *testing.T) {
	cases := []string{
		"http://127.0.0.1/hook",
		"http://[::1]/hook",
		"http://localhost/hook",
	}
	for _, raw := range cases {
		err := ValidateSubscription(Subscription{Name: "t", URL: raw})
		if err == nil {
			t.Errorf("URL %q must be rejected (loopback)", raw)
		}
	}
}

// TestValidateSubscription_RejectsCloudMetadata is the canonical
// "internal SSRF" target — AWS / GCP / Azure all expose unauthenticated
// metadata at 169.254.169.254. A leaked credential capture sent there
// is observable to anyone who can re-read the metadata service.
func TestValidateSubscription_RejectsCloudMetadata(t *testing.T) {
	err := ValidateSubscription(Subscription{Name: "t", URL: "http://169.254.169.254/latest/meta-data/"})
	if err == nil {
		t.Fatal("AWS IMDS endpoint must be rejected")
	}
	if !strings.Contains(err.Error(), "internal/loopback") {
		t.Errorf("error should mention internal/loopback target; got: %v", err)
	}
}

// TestValidateSubscription_RejectsRFC1918 covers private IP ranges
// commonly used for "the local k8s API" or peer infrastructure.
func TestValidateSubscription_RejectsRFC1918(t *testing.T) {
	cases := []string{
		"http://10.0.0.1/hook",
		"http://192.168.1.1/hook",
		"http://172.16.0.1/hook",
	}
	for _, raw := range cases {
		err := ValidateSubscription(Subscription{Name: "t", URL: raw})
		if err == nil {
			t.Errorf("URL %q must be rejected (RFC1918)", raw)
		}
	}
}

// TestValidateSubscription_RejectsNonHTTPSchemes ensures file://,
// ftp://, javascript:, etc. don't slip through the URL parse.
func TestValidateSubscription_RejectsNonHTTPSchemes(t *testing.T) {
	cases := []string{
		"file:///etc/passwd",
		"ftp://example.com/x",
		"javascript:alert(1)",
		"gopher://example.com:25/_HELO",
	}
	for _, raw := range cases {
		err := ValidateSubscription(Subscription{Name: "t", URL: raw})
		if err == nil {
			t.Errorf("URL %q must be rejected (non-http(s) scheme)", raw)
		}
	}
}

// TestValidateSubscription_AcceptsPublicHTTPS — the happy path. A
// well-formed external URL must validate cleanly.
func TestValidateSubscription_AcceptsPublicHTTPS(t *testing.T) {
	if err := ValidateSubscription(Subscription{Name: "t", URL: "https://example.com/webhook"}); err != nil {
		t.Errorf("public https URL should validate; got %v", err)
	}
}

// TestValidateSubscription_OverrideEnvAllowsInternal verifies the
// PROMPTZERO_WEBHOOK_ALLOW_INTERNAL escape hatch works for operators
// who deliberately wire internal sinks (homelab, on-prem pipelines).
func TestValidateSubscription_OverrideEnvAllowsInternal(t *testing.T) {
	orig := getenv
	getenv = func(k string) string {
		if k == "PROMPTZERO_WEBHOOK_ALLOW_INTERNAL" {
			return "1"
		}
		return ""
	}
	defer func() { getenv = orig }()

	if err := ValidateSubscription(Subscription{Name: "t", URL: "http://127.0.0.1/hook"}); err != nil {
		t.Errorf("loopback should be allowed when override is set; got %v", err)
	}
}

// TestValidateSubscription_RejectsEmptyURL is a smoke test for input
// validation.
func TestValidateSubscription_RejectsEmptyURL(t *testing.T) {
	if err := ValidateSubscription(Subscription{Name: "t"}); err == nil {
		t.Fatal("empty URL must error")
	}
}
