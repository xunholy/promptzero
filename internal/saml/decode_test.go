// SPDX-License-Identifier: AGPL-3.0-or-later

package saml

import (
	"encoding/base64"
	"strings"
	"testing"
)

// redirectVector is base64(raw-DEFLATE(authnRequestXML)), produced independently
// by Python's zlib (level 9, wbits -15) — the same standard DEFLATE real
// IdPs/SPs emit. It must inflate to authnRequestXML exactly.
const redirectVector = "fc9NCsIwEAXgq5Q5QKN1N7SBQjcF3egJxhpoIH9mJtDjaxWlblw+HnyP1zJ5l7AvMoezuRfDUi3eBcZX0UHJASOxZQzkDaNMeOlPR2zqHaYcJU7RQTUOHdB12jcHqIanYQOJjaGDWSQxKmVvqTYL+eSMYo6g29XHkbmYvFn8P0jMJq8w6A/MX7dVG1K/0+8z/QA="

const authnRequestXML = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="abc123" Destination="https://idp.example/sso"><saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://sp.example</saml:Issuer></samlp:AuthnRequest>`

// responseXML is a signed (Signature element present) SAML Response carrying an
// assertion — the POST-binding shape. The decoder must extract every field.
const responseXML = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_resp1" Version="2.0" IssueInstant="2024-01-01T00:00:00Z" Destination="https://sp.example/acs" InResponseTo="_req1">` +
	`<saml:Issuer>https://idp.example</saml:Issuer>` +
	`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature>` +
	`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
	`<saml:Assertion ID="_a1"><saml:Issuer>https://idp.example</saml:Issuer>` +
	`<saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">alice@victim.example</saml:NameID></saml:Subject>` +
	`<saml:Conditions NotBefore="2024-01-01T00:00:00Z" NotOnOrAfter="2024-01-01T01:00:00Z"><saml:AudienceRestriction><saml:Audience>https://sp.example/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
	`</saml:Assertion></samlp:Response>`

// TestRedirectBinding anchors the base64+DEFLATE path against the independent
// Python zlib vector.
func TestRedirectBinding(t *testing.T) {
	r, err := Decode(redirectVector)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.HasPrefix(r.Binding, "HTTP-Redirect") {
		t.Errorf("binding = %q, want HTTP-Redirect", r.Binding)
	}
	if r.XML != authnRequestXML {
		t.Errorf("inflated XML mismatch:\n got  %q\n want %q", r.XML, authnRequestXML)
	}
	if r.MessageType != "AuthnRequest" || r.ID != "abc123" {
		t.Errorf("type/id: %q / %q", r.MessageType, r.ID)
	}
	if r.Destination != "https://idp.example/sso" || r.Issuer != "https://sp.example" {
		t.Errorf("destination/issuer: %q / %q", r.Destination, r.Issuer)
	}
	if r.SignaturePresent {
		t.Error("AuthnRequest has no signature")
	}
}

// TestPostBinding anchors the plain-base64 path + field extraction on a signed
// Response.
func TestPostBinding(t *testing.T) {
	token := base64.StdEncoding.EncodeToString([]byte(responseXML))
	r, err := Decode(token)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Binding != "HTTP-POST (raw)" {
		t.Errorf("binding = %q, want HTTP-POST (raw)", r.Binding)
	}
	checks := map[string]string{
		"message_type":   r.MessageType,
		"id":             r.ID,
		"version":        r.Version,
		"destination":    r.Destination,
		"in_response_to": r.InResponseTo,
		"issuer":         r.Issuer,
		"name_id":        r.NameID,
		"status":         r.StatusCode,
		"not_before":     r.ConditionsNotBefore,
		"not_on_after":   r.ConditionsNotOnOrAfter,
	}
	want := map[string]string{
		"message_type":   "Response",
		"id":             "_resp1",
		"version":        "2.0",
		"destination":    "https://sp.example/acs",
		"in_response_to": "_req1",
		"issuer":         "https://idp.example",
		"name_id":        "alice@victim.example",
		"status":         "urn:oasis:names:tc:SAML:2.0:status:Success",
		"not_before":     "2024-01-01T00:00:00Z",
		"not_on_after":   "2024-01-01T01:00:00Z",
	}
	for k, got := range checks {
		if got != want[k] {
			t.Errorf("%s = %q, want %q", k, got, want[k])
		}
	}
	if len(r.Audiences) != 1 || r.Audiences[0] != "https://sp.example/metadata" {
		t.Errorf("audiences = %v", r.Audiences)
	}
	if !r.SignaturePresent || r.SignatureCount != 1 {
		t.Errorf("signature: present=%v count=%d, want true/1", r.SignaturePresent, r.SignatureCount)
	}
}

// TestPercentEncoded confirms a URL-pasted (percent-encoded) value is handled.
func TestPercentEncoded(t *testing.T) {
	token := base64.StdEncoding.EncodeToString([]byte(responseXML))
	// Percent-encode the base64 '+' '/' '=' as they'd appear in a URL.
	enc := strings.NewReplacer("+", "%2B", "/", "%2F", "=", "%3D").Replace(token)
	r, err := Decode(enc)
	if err != nil {
		t.Fatalf("Decode(percent-encoded): %v", err)
	}
	if r.MessageType != "Response" {
		t.Errorf("percent-encoded decode failed: %+v", r)
	}
}

func TestRejectsMalformed(t *testing.T) {
	for _, c := range []string{
		"",
		"@@@not base64@@@",
		base64.StdEncoding.EncodeToString([]byte("not xml at all, just text")),
	} {
		if _, err := Decode(c); err == nil {
			t.Errorf("Decode(%q): want error, got nil", c)
		}
	}
}
