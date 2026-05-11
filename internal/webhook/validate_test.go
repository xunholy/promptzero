package webhook

import (
	"net"
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

// TestValidateSubscription_RejectsCGNAT pins the v0.169 contract
// addition: 100.64.0.0/10 (RFC 6598 carrier-grade NAT) joins the
// internal-IP block-list. On-prem deployments routing CGNAT to
// internal services would otherwise have a webhook bypass the
// SSRF guard — Go's net.IP.IsPrivate only covers RFC1918, not
// CGNAT.
func TestValidateSubscription_RejectsCGNAT(t *testing.T) {
	cases := []string{
		"http://100.64.0.1/hook",      // start of range
		"http://100.127.255.254/hook", // end of range
		"http://100.100.100.100/hook", // middle
	}
	for _, raw := range cases {
		err := ValidateSubscription(Subscription{Name: "t", URL: raw})
		if err == nil {
			t.Errorf("URL %q must be rejected (CGNAT 100.64.0.0/10)", raw)
		}
	}
}

// TestValidateSubscription_AcceptsJustOutsideCGNAT pins the
// boundary — addresses just outside the 100.64.0.0/10 range must
// still pass so legitimate public IPs that happen to start with
// "100." (e.g. 100.0.0.1, 100.128.0.0) aren't blocked.
func TestValidateSubscription_AcceptsJustOutsideCGNAT(t *testing.T) {
	// We can't easily test acceptance against a public-routable IP
	// without DNS resolution. Use isInternalIP directly to pin the
	// boundary semantics without resolving anything.
	cases := []string{
		"100.63.255.255", // last IP before CGNAT
		"100.128.0.0",    // first IP after CGNAT
	}
	for _, ip := range cases {
		parsed := net.ParseIP(ip)
		if isInternalIP(parsed) {
			t.Errorf("isInternalIP(%s) = true; want false (just outside CGNAT range)", ip)
		}
	}
}

// TestIsInternalIP_IPv6BypassGaps pins the v0.170 additions:
// site-local multicast (ff05::), org-local multicast (ff08::), and
// deprecated site-local unicast (fec0::/10) all join the
// internal-IP block-list. Go's IsLinkLocalMulticast covers only
// ff02::, and no helper flags fec0::* — both are documented
// SSRF-bypass vectors for IPv6 LAN attacks.
func TestIsInternalIP_IPv6BypassGaps(t *testing.T) {
	cases := []struct {
		ip   string
		note string
	}{
		{"ff05::1", "site-local multicast (RFC 4291)"},
		{"ff08::1", "org-local multicast (RFC 4291)"},
		{"fec0::1", "deprecated site-local unicast (RFC 3879)"},
		// Sanity: IPv4 multicast also flagged via IsMulticast.
		{"224.0.0.1", "IPv4 link-local multicast"},
	}
	for _, c := range cases {
		parsed := net.ParseIP(c.ip)
		if !isInternalIP(parsed) {
			t.Errorf("isInternalIP(%s) = false; want true (%s)", c.ip, c.note)
		}
	}
}

// TestIsInternalIP_PublicIPv6Passes pins the boundary — well-formed
// public IPv6 addresses outside the new ranges still validate.
func TestIsInternalIP_PublicIPv6Passes(t *testing.T) {
	cases := []string{
		"2606:4700:4700::1111", // Cloudflare DNS
		"2001:4860:4860::8888", // Google DNS
	}
	for _, ip := range cases {
		parsed := net.ParseIP(ip)
		if isInternalIP(parsed) {
			t.Errorf("isInternalIP(%s) = true; want false (public IPv6)", ip)
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

// TestValidateSubscription_RejectsUnknownEvent locks the typo trap:
// `events: [tool_finsished]` (typo) used to silently never fire.
// ValidateSubscription now reports the unknown name with the
// allowed list so the operator can fix it at config-load time.
func TestValidateSubscription_RejectsUnknownEvent(t *testing.T) {
	cases := []Event{
		"tool_finsished", // typo — missing 'i'
		"audit_warning",  // not in the canonical set
		"",               // empty event name
		"TOOL_FINISHED",  // wrong case
	}
	for _, e := range cases {
		t.Run(string(e), func(t *testing.T) {
			err := ValidateSubscription(Subscription{
				Name:   "t",
				URL:    "https://example.com/hook",
				Events: []Event{e},
			})
			if err == nil {
				t.Errorf("event %q should error", e)
			}
		})
	}
}

// TestValidateSubscription_AcceptsKnownEvents covers all 7 canonical
// values; future additions to the const block must be reflected in
// knownEvents or this test fails.
func TestValidateSubscription_AcceptsKnownEvents(t *testing.T) {
	for _, e := range []Event{
		EventToolFinished, EventRiskPrompted, EventRiskDenied,
		EventWorkflowCompleted, EventAuditCritical,
		EventSessionStarted, EventSessionEnded,
	} {
		t.Run(string(e), func(t *testing.T) {
			err := ValidateSubscription(Subscription{
				Name:   "t",
				URL:    "https://example.com/hook",
				Events: []Event{e},
			})
			if err != nil {
				t.Errorf("event %q should validate, got: %v", e, err)
			}
		})
	}
}

// TestValidateSubscription_EmptyEventsAllowsAll preserves the
// existing semantics: a Subscription with no Events filter receives
// every event, not nothing.
func TestValidateSubscription_EmptyEventsAllowsAll(t *testing.T) {
	err := ValidateSubscription(Subscription{
		Name: "t",
		URL:  "https://example.com/hook",
	})
	if err != nil {
		t.Errorf("empty Events should validate (means all-events): %v", err)
	}
}
