package xmpp

import (
	"encoding/hex"
	"testing"
)

// toHex converts a plain string to its hex representation so tests
// can build payloads the same way as real network captures.
func toHex(s string) string {
	return hex.EncodeToString([]byte(s))
}

func TestDecode_StreamOpen(t *testing.T) {
	xml := `<?xml version='1.0'?><stream:stream to='example.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "stream_open" {
		t.Errorf("stanza_type=%q, want stream_open", r.StanzaType)
	}
	if r.ToDomain != "example.com" {
		t.Errorf("to_domain=%q, want example.com", r.ToDomain)
	}
	if r.Version != "1.0" {
		t.Errorf("version=%q, want 1.0", r.Version)
	}
	if r.Xmlns != "jabber:client" {
		t.Errorf("xmlns=%q, want jabber:client", r.Xmlns)
	}
	if !r.IsStreamNegotiation {
		t.Error("expected is_stream_negotiation=true")
	}
}

func TestDecode_StreamFeatures(t *testing.T) {
	xml := `<stream:features>` +
		`<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>` +
		`<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>` +
		`<mechanism>SCRAM-SHA-1</mechanism>` +
		`<mechanism>PLAIN</mechanism>` +
		`</mechanisms>` +
		`<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'/>` +
		`</stream:features>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "stream_features" {
		t.Errorf("stanza_type=%q, want stream_features", r.StanzaType)
	}
	if !r.IsStreamNegotiation {
		t.Error("expected is_stream_negotiation=true")
	}
	if !r.HasStartTLS {
		t.Error("expected has_starttls=true")
	}
	if !r.StartTLSRequired {
		t.Error("expected starttls_required=true")
	}
	if len(r.Mechanisms) != 2 {
		t.Fatalf("mechanisms len=%d, want 2", len(r.Mechanisms))
	}
	if r.Mechanisms[0] != "SCRAM-SHA-1" {
		t.Errorf("mechanisms[0]=%q, want SCRAM-SHA-1", r.Mechanisms[0])
	}
	if r.Mechanisms[1] != "PLAIN" {
		t.Errorf("mechanisms[1]=%q, want PLAIN", r.Mechanisms[1])
	}
}

func TestDecode_AuthPLAIN(t *testing.T) {
	// base64("\x00admin\x00secret") = AGFkbWluAHNlY3JldA==
	xml := `<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='PLAIN'>AGFkbWluAHNlY3JldA==</auth>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "auth" {
		t.Errorf("stanza_type=%q, want auth", r.StanzaType)
	}
	if r.Mechanism != "PLAIN" {
		t.Errorf("mechanism=%q, want PLAIN", r.Mechanism)
	}
	// auth data length is the base64 string length, not the decoded length
	if r.AuthDataLength != len("AGFkbWluAHNlY3JldA==") {
		t.Errorf("auth_data_length=%d, want %d", r.AuthDataLength, len("AGFkbWluAHNlY3JldA=="))
	}
	if !r.IsCleartextAuth {
		t.Error("expected is_cleartext_auth=true for PLAIN")
	}
	if r.CleartextAuthFlag == "" {
		t.Error("expected non-empty cleartext_auth_flag")
	}
}

func TestDecode_AuthSCRAM(t *testing.T) {
	xml := `<auth xmlns='urn:ietf:params:xml:ns:xmpp-sasl' mechanism='SCRAM-SHA-1'>biwsbj11c2Vy</auth>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "auth" {
		t.Errorf("stanza_type=%q, want auth", r.StanzaType)
	}
	if r.Mechanism != "SCRAM-SHA-1" {
		t.Errorf("mechanism=%q, want SCRAM-SHA-1", r.Mechanism)
	}
	if r.IsCleartextAuth {
		t.Error("SCRAM-SHA-1 should not flag cleartext auth")
	}
}

func TestDecode_MessageWithBody(t *testing.T) {
	xml := `<message from='alice@example.com/mobile' to='bob@example.com' id='msg1' type='chat'>` +
		`<body>Hello!</body>` +
		`</message>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "message" {
		t.Errorf("stanza_type=%q, want message", r.StanzaType)
	}
	if r.FromJID != "alice@example.com/mobile" {
		t.Errorf("from_jid=%q, want alice@example.com/mobile", r.FromJID)
	}
	if r.ToJID != "bob@example.com" {
		t.Errorf("to_jid=%q, want bob@example.com", r.ToJID)
	}
	if r.StanzaID != "msg1" {
		t.Errorf("stanza_id=%q, want msg1", r.StanzaID)
	}
	if r.StanzaSubtype != "chat" {
		t.Errorf("stanza_subtype=%q, want chat", r.StanzaSubtype)
	}
	if !r.HasBody {
		t.Error("expected has_body=true")
	}
}

func TestDecode_MessageNoBody(t *testing.T) {
	xml := `<message from='server@example.com' to='user@example.com' type='headline' id='hl1'/>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "message" {
		t.Errorf("stanza_type=%q, want message", r.StanzaType)
	}
	if r.HasBody {
		t.Error("expected has_body=false for message without body")
	}
}

func TestDecode_Presence(t *testing.T) {
	xml := `<presence from='user@example.com/laptop' to='contact@example.com'/>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "presence" {
		t.Errorf("stanza_type=%q, want presence", r.StanzaType)
	}
	if r.FromJID != "user@example.com/laptop" {
		t.Errorf("from_jid=%q, want user@example.com/laptop", r.FromJID)
	}
}

func TestDecode_IQBind(t *testing.T) {
	xml := `<iq type='set' id='bind1'>` +
		`<bind xmlns='urn:ietf:params:xml:ns:xmpp-bind'>` +
		`<resource>myapp</resource>` +
		`</bind>` +
		`</iq>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "iq" {
		t.Errorf("stanza_type=%q, want iq", r.StanzaType)
	}
	if r.StanzaSubtype != "set" {
		t.Errorf("stanza_subtype=%q, want set", r.StanzaSubtype)
	}
	if r.StanzaID != "bind1" {
		t.Errorf("stanza_id=%q, want bind1", r.StanzaID)
	}
	if r.IQNamespace != "urn:ietf:params:xml:ns:xmpp-bind" {
		t.Errorf("iq_namespace=%q, want urn:ietf:params:xml:ns:xmpp-bind", r.IQNamespace)
	}
}

func TestDecode_IQRoster(t *testing.T) {
	xml := `<iq from='user@example.com/res' type='get' id='roster1'>` +
		`<query xmlns='jabber:iq:roster'/>` +
		`</iq>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "iq" {
		t.Errorf("stanza_type=%q, want iq", r.StanzaType)
	}
	if r.IQNamespace != "jabber:iq:roster" {
		t.Errorf("iq_namespace=%q, want jabber:iq:roster", r.IQNamespace)
	}
}

func TestDecode_StartTLS(t *testing.T) {
	xml := `<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "starttls" {
		t.Errorf("stanza_type=%q, want starttls", r.StanzaType)
	}
}

func TestDecode_Success(t *testing.T) {
	xml := `<success xmlns='urn:ietf:params:xml:ns:xmpp-sasl'/>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "success" {
		t.Errorf("stanza_type=%q, want success", r.StanzaType)
	}
}

func TestDecode_Failure(t *testing.T) {
	xml := `<failure xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><not-authorized/></failure>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "failure" {
		t.Errorf("stanza_type=%q, want failure", r.StanzaType)
	}
}

func TestDecode_StreamClose(t *testing.T) {
	xml := `</stream:stream>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.StanzaType != "stream_close" {
		t.Errorf("stanza_type=%q, want stream_close", r.StanzaType)
	}
}

func TestDecode_StripSeparators(t *testing.T) {
	// Test that separators are accepted in hex input.
	xml := `<presence/>`
	plain := toHex(xml)
	// Insert colons as separators.
	var colonHex string
	for i := 0; i < len(plain); i += 2 {
		if i > 0 {
			colonHex += ":"
		}
		colonHex += plain[i : i+2]
	}
	r, err := Decode(colonHex)
	if err != nil {
		t.Fatalf("colon-separated hex: %v", err)
	}
	if r.StanzaType != "presence" {
		t.Errorf("stanza_type=%q, want presence", r.StanzaType)
	}
}

func TestDecode_TotalBytes(t *testing.T) {
	xml := `<presence/>`
	r, err := Decode(toHex(xml))
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalBytes != len(xml) {
		t.Errorf("total_bytes=%d, want %d", r.TotalBytes, len(xml))
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecode_RejectsOddHex(t *testing.T) {
	_, err := Decode("abc")
	if err == nil {
		t.Fatal("want error for odd-length hex")
	}
}

func TestDecode_RejectsInvalidHex(t *testing.T) {
	_, err := Decode("zzzz")
	if err == nil {
		t.Fatal("want error for invalid hex")
	}
}
