package sip

import (
	"strings"
	"testing"
)

// TestDecode_INVITE pins a canonical SIP INVITE request with
// Via, From, To, Call-ID, CSeq, Contact, and an SDP body.
func TestDecode_INVITE(t *testing.T) {
	msg := "INVITE sip:bob@biloxi.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds\r\n" +
		"Max-Forwards: 70\r\n" +
		"To: Bob <sip:bob@biloxi.example.com>\r\n" +
		"From: Alice <sip:alice@atlanta.example.com>;tag=1928301774\r\n" +
		"Call-ID: a84b4c76e66710\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Contact: <sip:alice@pc33.atlanta.example.com>\r\n" +
		"Content-Type: application/sdp\r\n" +
		"Content-Length: 142\r\n" +
		"\r\n" +
		"v=0\r\n" +
		"o=alice 2890844526 2890844526 IN IP4 pc33.atlanta.example.com\r\n" +
		"s=Session SDP\r\n" +
		"c=IN IP4 pc33.atlanta.example.com\r\n" +
		"t=0 0\r\n" +
		"m=audio 49170 RTP/AVP 0\r\n" +
		"a=rtpmap:0 PCMU/8000\r\n"
	got, err := Decode(msg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.IsRequest {
		t.Error("IsRequest = false; want true")
	}
	if got.Method != "INVITE" {
		t.Errorf("Method = %q", got.Method)
	}
	if got.RequestURI != "sip:bob@biloxi.example.com" {
		t.Errorf("RequestURI = %q", got.RequestURI)
	}
	if got.Version != "SIP/2.0" {
		t.Errorf("Version = %q", got.Version)
	}
	if got.From != "Alice <sip:alice@atlanta.example.com>;tag=1928301774" {
		t.Errorf("From = %q", got.From)
	}
	if got.To != "Bob <sip:bob@biloxi.example.com>" {
		t.Errorf("To = %q", got.To)
	}
	if got.CallID != "a84b4c76e66710" {
		t.Errorf("CallID = %q", got.CallID)
	}
	if got.CSeq == nil || got.CSeq.Sequence != 314159 || got.CSeq.Method != "INVITE" {
		t.Errorf("CSeq = %v", got.CSeq)
	}
	if len(got.Via) != 1 {
		t.Errorf("Via count = %d", len(got.Via))
	}
	if len(got.Contact) != 1 {
		t.Errorf("Contact count = %d", len(got.Contact))
	}
	if got.ContentType != "application/sdp" {
		t.Errorf("ContentType = %q", got.ContentType)
	}
	if got.MaxForwards != 70 {
		t.Errorf("MaxForwards = %d", got.MaxForwards)
	}
	if got.SDP == nil {
		t.Fatal("SDP nil")
	}
	if got.SDP.Version != "0" {
		t.Errorf("SDP.Version = %q", got.SDP.Version)
	}
	if got.SDP.SessionName != "Session SDP" {
		t.Errorf("SDP.SessionName = %q", got.SDP.SessionName)
	}
	if len(got.SDP.Media) != 1 {
		t.Fatalf("SDP.Media count = %d", len(got.SDP.Media))
	}
	m0 := got.SDP.Media[0]
	if m0.Type != "audio" {
		t.Errorf("SDP.Media[0].Type = %q", m0.Type)
	}
	if m0.Port != 49170 {
		t.Errorf("SDP.Media[0].Port = %d", m0.Port)
	}
	if m0.Protocol != "RTP/AVP" {
		t.Errorf("SDP.Media[0].Protocol = %q", m0.Protocol)
	}
	if len(m0.PayloadTypes) != 1 || m0.PayloadTypes[0] != "0" {
		t.Errorf("SDP.Media[0].PayloadTypes = %v", m0.PayloadTypes)
	}
	if len(m0.Attributes) != 1 || m0.Attributes[0] != "rtpmap:0 PCMU/8000" {
		t.Errorf("SDP.Media[0].Attributes = %v", m0.Attributes)
	}
}

// TestDecode_200OK pins a 200 OK response.
func TestDecode_200OK(t *testing.T) {
	msg := "SIP/2.0 200 OK\r\n" +
		"Via: SIP/2.0/UDP server10.example.com;branch=z9hG4bKnashds8\r\n" +
		"To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n" +
		"From: Alice <sip:alice@example.com>;tag=1928301774\r\n" +
		"Call-ID: a84b4c76e66710\r\n" +
		"CSeq: 314159 INVITE\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	got, err := Decode(msg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.IsResponse {
		t.Error("IsResponse = false; want true")
	}
	if got.StatusCode != 200 {
		t.Errorf("StatusCode = %d", got.StatusCode)
	}
	if got.StatusName != "OK" {
		t.Errorf("StatusName = %q", got.StatusName)
	}
	if got.StatusReason != "OK" {
		t.Errorf("StatusReason = %q", got.StatusReason)
	}
	if got.CSeq == nil || got.CSeq.Method != "INVITE" {
		t.Errorf("CSeq = %v", got.CSeq)
	}
}

// TestDecode_StatusCodes pins a handful of status codes
// across all six response classes.
func TestDecode_StatusCodes(t *testing.T) {
	cases := []struct {
		line     string
		code     int
		wantName string
	}{
		{"SIP/2.0 100 Trying", 100, "Trying"},
		{"SIP/2.0 180 Ringing", 180, "Ringing"},
		{"SIP/2.0 200 OK", 200, "OK"},
		{"SIP/2.0 302 Moved Temporarily", 302, "Moved Temporarily"},
		{"SIP/2.0 401 Unauthorized", 401, "Unauthorized"},
		{"SIP/2.0 404 Not Found", 404, "Not Found"},
		{"SIP/2.0 486 Busy Here", 486, "Busy Here"},
		{"SIP/2.0 500 Server Internal Error", 500, "Server Internal Error"},
		{"SIP/2.0 503 Service Unavailable", 503, "Service Unavailable"},
		{"SIP/2.0 603 Decline", 603, "Decline"},
	}
	for _, c := range cases {
		// Minimal full message with the status line + blank body
		msg := c.line + "\r\nContent-Length: 0\r\n\r\n"
		got, err := Decode(msg)
		if err != nil {
			t.Fatalf("Decode(%q): %v", c.line, err)
		}
		if got.StatusCode != c.code {
			t.Errorf("%s: StatusCode = %d", c.line, got.StatusCode)
		}
		if got.StatusName != c.wantName {
			t.Errorf("%s: StatusName = %q; want %q", c.line, got.StatusName, c.wantName)
		}
	}
}

// TestDecode_CompactHeaders pins the compact-form header
// expansion (RFC 3261 §7.3.3).
func TestDecode_CompactHeaders(t *testing.T) {
	msg := "REGISTER sip:registrar.example.com SIP/2.0\r\n" +
		"v: SIP/2.0/UDP my.host.example.com\r\n" +
		"t: <sip:user@example.com>\r\n" +
		"f: <sip:user@example.com>;tag=abc\r\n" +
		"i: 12345\r\n" +
		"CSeq: 1 REGISTER\r\n" +
		"m: <sip:user@my.host.example.com>\r\n" +
		"l: 0\r\n" +
		"\r\n"
	got, err := Decode(msg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.From != "<sip:user@example.com>;tag=abc" {
		t.Errorf("From = %q", got.From)
	}
	if got.To != "<sip:user@example.com>" {
		t.Errorf("To = %q", got.To)
	}
	if got.CallID != "12345" {
		t.Errorf("CallID = %q", got.CallID)
	}
	if len(got.Contact) != 1 {
		t.Errorf("Contact count = %d", len(got.Contact))
	}
	if len(got.Via) != 1 {
		t.Errorf("Via count = %d", len(got.Via))
	}
	if got.ContentLength != 0 {
		t.Errorf("ContentLength = %d", got.ContentLength)
	}
}

// TestDecode_MultipleVia pins the multi-value Via list when
// a request traverses multiple proxies.
func TestDecode_MultipleVia(t *testing.T) {
	msg := "BYE sip:bob@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP proxy2.example.com;branch=z9hG4bK222\r\n" +
		"Via: SIP/2.0/UDP proxy1.example.com;branch=z9hG4bK111\r\n" +
		"Via: SIP/2.0/UDP alice.example.com;branch=z9hG4bK000\r\n" +
		"Call-ID: 12345\r\n" +
		"CSeq: 2 BYE\r\n" +
		"\r\n"
	got, err := Decode(msg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Via) != 3 {
		t.Errorf("Via count = %d; want 3", len(got.Via))
	}
}

// TestDecode_REGISTER pins a REGISTER request with
// Authorization header (carried as-is in the header list).
func TestDecode_REGISTER(t *testing.T) {
	msg := "REGISTER sip:registrar.example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP bob.example.com;branch=z9hG4bK74bf9\r\n" +
		"Max-Forwards: 70\r\n" +
		"From: <sip:bob@example.com>;tag=456248\r\n" +
		"To: <sip:bob@example.com>\r\n" +
		"Call-ID: 843817637684230@998sdasdh09\r\n" +
		"CSeq: 1826 REGISTER\r\n" +
		"Contact: <sip:bob@192.0.2.4>\r\n" +
		"Authorization: Digest username=\"bob\", realm=\"example.com\", nonce=\"abc\", uri=\"sip:registrar.example.com\", response=\"def\"\r\n" +
		"Expires: 7200\r\n" +
		"Content-Length: 0\r\n" +
		"\r\n"
	got, err := Decode(msg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Method != "REGISTER" {
		t.Errorf("Method = %q", got.Method)
	}
	// Verify Authorization header is present in the raw list
	var auth *Header
	for _, h := range got.Headers {
		if strings.EqualFold(h.Name, "Authorization") {
			auth = h
			break
		}
	}
	if auth == nil {
		t.Fatal("Authorization header not found")
	}
	if !strings.HasPrefix(auth.Value, "Digest ") {
		t.Errorf("Authorization = %q", auth.Value)
	}
}

// TestDecode_HeaderContinuation pins the line-continuation
// rule (lines starting with whitespace fold into the
// previous header).
func TestDecode_HeaderContinuation(t *testing.T) {
	msg := "OPTIONS sip:user@example.com SIP/2.0\r\n" +
		"Via: SIP/2.0/UDP first.example.com\r\n" +
		"   ;branch=z9hG4bKlong\r\n" +
		"Call-ID: 99\r\n" +
		"CSeq: 1 OPTIONS\r\n" +
		"\r\n"
	got, err := Decode(msg)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(got.Via) != 1 {
		t.Errorf("Via count = %d", len(got.Via))
	}
	if !strings.Contains(got.Via[0], "branch=z9hG4bKlong") {
		t.Errorf("Via continuation not folded: %q", got.Via[0])
	}
}

// TestDecode_MissingStartLine rejects empty input.
func TestDecode_MissingStartLine(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
}

// TestDecode_MalformedRequestLine rejects request lines
// missing fields.
func TestDecode_MalformedRequestLine(t *testing.T) {
	if _, err := Decode("INVITE\r\n\r\n"); err == nil {
		t.Error("malformed request line: want error")
	}
}

// TestDecode_MalformedStatusLine rejects non-numeric status
// codes.
func TestDecode_MalformedStatusLine(t *testing.T) {
	if _, err := Decode("SIP/2.0 ABC OK\r\n\r\n"); err == nil {
		t.Error("non-numeric status: want error")
	}
}

// TestStatusNameTable spot-checks the table coverage.
func TestStatusNameTable(t *testing.T) {
	cases := map[int]string{
		100: "Trying",
		180: "Ringing",
		200: "OK",
		301: "Moved Permanently",
		401: "Unauthorized",
		407: "Proxy Authentication Required",
		486: "Busy Here",
		503: "Service Unavailable",
		603: "Decline",
	}
	for c, want := range cases {
		if got := statusName(c); got != want {
			t.Errorf("statusName(%d) = %q; want %q", c, got, want)
		}
	}
}

// TestParseCSeq spot-checks the CSeq parser.
func TestParseCSeq(t *testing.T) {
	c := parseCSeq("314159 INVITE")
	if c == nil {
		t.Fatal("parseCSeq nil")
	}
	if c.Sequence != 314159 {
		t.Errorf("Sequence = %d", c.Sequence)
	}
	if c.Method != "INVITE" {
		t.Errorf("Method = %q", c.Method)
	}
	// Bad CSeq returns nil
	if parseCSeq("abc INVITE") != nil {
		t.Error("non-numeric seq: want nil")
	}
	if parseCSeq("314159") != nil {
		t.Error("missing method: want nil")
	}
}

// TestExpandCompactName spot-checks.
func TestExpandCompactName(t *testing.T) {
	cases := map[string]string{
		"m": "Contact",
		"v": "Via",
		"l": "Content-Length",
		"t": "To",
		"f": "From",
		"i": "Call-ID",
		"c": "Content-Type",
	}
	for raw, want := range cases {
		if got := expandCompactName(raw); got != want {
			t.Errorf("expandCompactName(%q) = %q; want %q", raw, got, want)
		}
	}
	// Non-compact names pass through unchanged
	if got := expandCompactName("Via"); got != "Via" {
		t.Errorf("Via passthrough = %q", got)
	}
}
