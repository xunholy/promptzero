package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

// TestXMPPDecodeHandler_StreamFeatures pins the stream negotiation shape.
func TestXMPPDecodeHandler_StreamFeatures(t *testing.T) {
	xml := `<stream:features>` +
		`<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>` +
		`<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>` +
		`<mechanism>SCRAM-SHA-1</mechanism>` +
		`<mechanism>PLAIN</mechanism>` +
		`</mechanisms>` +
		`</stream:features>`
	hexStr := hex.EncodeToString([]byte(xml))

	out, err := xmppDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hexStr})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"stanza_type": "stream_features"`,
		`"is_stream_negotiation": true`,
		`"has_starttls": true`,
		`"starttls_required": true`,
		`"SCRAM-SHA-1"`,
		`"PLAIN"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestXMPPDecodeHandler_AuthPLAIN pins the cleartext credential
// exposure classification.
func TestXMPPDecodeHandler_AuthPLAIN(t *testing.T) {
	// base64("\x00admin\x00secret") = AGFkbWluAHNlY3JldA==
	xml := `<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGFkbWluAHNlY3JldA==</auth>`
	hexStr := hex.EncodeToString([]byte(xml))

	out, err := xmppDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hexStr})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"stanza_type": "auth"`,
		`"mechanism": "PLAIN"`,
		`"is_cleartext_auth": true`,
		`cleartext`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
	// Verify auth_data_length is present and non-zero.
	if !strings.Contains(out, `"auth_data_length"`) {
		t.Errorf("expected auth_data_length field in output:\n%s", out)
	}
}

// TestXMPPDecodeHandler_StreamOpen pins the stream opening shape.
func TestXMPPDecodeHandler_StreamOpen(t *testing.T) {
	xml := `<?xml version='1.0'?><stream:stream to='example.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`
	hexStr := hex.EncodeToString([]byte(xml))

	out, err := xmppDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hexStr})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"stanza_type": "stream_open"`,
		`"to_domain": "example.com"`,
		`"is_stream_negotiation": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestXMPPDecodeHandler_RejectsEmpty verifies error on missing hex.
func TestXMPPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := xmppDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
