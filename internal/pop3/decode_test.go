package pop3

import (
	"encoding/hex"
	"strings"
	"testing"
)

// hexify converts an ASCII POP3 message to hex for feeding the
// hex-input decoder (mirrors operator workflow of pasting
// bytes from a packet capture).
func hexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestDecodeBanner pins the canonical +OK greeting — the MTA
// banner-fingerprinting goldmine.
func TestDecodeBanner(t *testing.T) {
	msg := "+OK Dovecot (Ubuntu) ready.\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindResponse {
		t.Errorf("kind: got %q want Response", r.Kind)
	}
	if r.Status != "+OK" {
		t.Errorf("status: got %q want +OK", r.Status)
	}
	if r.StatusText != "Dovecot (Ubuntu) ready." {
		t.Errorf("statusText: got %q", r.StatusText)
	}
}

// TestDecodeAPOPBanner pins the legacy APOP banner that leaks
// the MD5-challenge timestamp (canonical APOP attack surface).
func TestDecodeAPOPBanner(t *testing.T) {
	msg := "+OK POP3 mail.example.com v2024.07 server ready <1896.697170952@dbc.mtview.ca.us>\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.StatusText, "<1896.697170952@dbc.mtview.ca.us>") {
		t.Errorf("APOP timestamp not surfaced: %q", r.StatusText)
	}
}

// TestDecodeUSERCommand pins the canonical username-disclosure
// command.
func TestDecodeUSERCommand(t *testing.T) {
	msg := "USER admin\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindCommand {
		t.Errorf("kind: got %q want Command", r.Kind)
	}
	if r.Verb != "USER" {
		t.Errorf("verb: got %q want USER", r.Verb)
	}
	if r.Argument != "admin" {
		t.Errorf("argument: got %q want admin", r.Argument)
	}
}

// TestDecodePASSCommand pins the cleartext-password disclosure.
func TestDecodePASSCommand(t *testing.T) {
	msg := "PASS hunter2\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "PASS" {
		t.Errorf("verb: got %q want PASS", r.Verb)
	}
	if r.Argument != "hunter2" {
		t.Errorf("argument: got %q want hunter2", r.Argument)
	}
}

// TestDecodeAPOPCommand pins the APOP MD5-challenge command.
func TestDecodeAPOPCommand(t *testing.T) {
	msg := "APOP admin c4c9334bac560ecc979e58001b3e22fb\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "APOP" {
		t.Errorf("verb: got %q want APOP", r.Verb)
	}
	if !strings.HasPrefix(r.Argument, "admin ") {
		t.Errorf("argument: got %q", r.Argument)
	}
}

// TestDecodeAuthFailedResponse pins -ERR for failed
// authentication — the brute-force feedback signal.
func TestDecodeAuthFailedResponse(t *testing.T) {
	msg := "-ERR Authentication failed.\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Status != "-ERR" {
		t.Errorf("status: got %q want -ERR", r.Status)
	}
	if r.StatusText != "Authentication failed." {
		t.Errorf("statusText: got %q", r.StatusText)
	}
}

// TestDecodeCAPAMultilineResponse pins the canonical CAPA
// response — multi-line, with "." terminator — that exposes
// STLS / SASL mechanisms.
func TestDecodeCAPAMultilineResponse(t *testing.T) {
	msg := "+OK Capability list follows\r\n" +
		"TOP\r\n" +
		"USER\r\n" +
		"SASL CRAM-MD5 PLAIN LOGIN\r\n" +
		"UIDL\r\n" +
		"STLS\r\n" +
		"PIPELINING\r\n" +
		".\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Status != "+OK" {
		t.Errorf("status: got %q want +OK", r.Status)
	}
	if len(r.DataLines) != 6 {
		t.Errorf("data lines: got %d want 6", len(r.DataLines))
	}
	want := []string{"TOP", "USER", "SASL CRAM-MD5 PLAIN LOGIN",
		"UIDL", "STLS", "PIPELINING"}
	for i, w := range want {
		if i < len(r.DataLines) && r.DataLines[i] != w {
			t.Errorf("line[%d]: got %q want %q", i, r.DataLines[i], w)
		}
	}
}

// TestDecodeRETRMultilineResponse pins a RETR response with
// body content (byte-stuffing test).
func TestDecodeRETRMultilineResponse(t *testing.T) {
	msg := "+OK 245 octets\r\n" +
		"From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: Hello\r\n" +
		"\r\n" +
		"Hi Bob,\r\n" +
		"..This line started with a dot, byte-stuffed on the wire.\r\n" +
		"Cheers!\r\n" +
		".\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Status != "+OK" {
		t.Errorf("status: got %q", r.Status)
	}
	// Byte-stuffing removal: the line "..This line started..."
	// should have its leading "." stripped to ".This line...".
	found := false
	for _, ln := range r.DataLines {
		if strings.HasPrefix(ln, ".This line started") {
			found = true
		}
	}
	if !found {
		t.Errorf("byte-stuffing removal failed; data lines: %v", r.DataLines)
	}
}

// TestDecodeSTLSCommand pins the STLS upgrade trigger.
func TestDecodeSTLSCommand(t *testing.T) {
	msg := "STLS\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "STLS" {
		t.Errorf("verb: got %q want STLS", r.Verb)
	}
	if r.Argument != "" {
		t.Errorf("argument: should be empty, got %q", r.Argument)
	}
}

// TestDecodeSTATCommand pins the STAT command (mailbox status
// query).
func TestDecodeSTATCommand(t *testing.T) {
	msg := "STAT\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "STAT" {
		t.Errorf("verb: got %q want STAT", r.Verb)
	}
}

// TestDecodeSTATResponse pins the +OK <count> <octets> reply.
func TestDecodeSTATResponse(t *testing.T) {
	msg := "+OK 5 3275\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StatusText != "5 3275" {
		t.Errorf("statusText: got %q want '5 3275'", r.StatusText)
	}
}

// TestClassifyFirstLine covers each kind boundary.
func TestClassifyFirstLine(t *testing.T) {
	cases := map[string]MessageKind{
		"+OK Banner":   KindResponse,
		"-ERR Bad cmd": KindResponse,
		"USER admin":   KindCommand,
		"stat":         KindCommand,
		"":             KindUnknown,
		"~?invalid":    KindUnknown,
	}
	for in, want := range cases {
		if got := classifyFirstLine(in); got != want {
			t.Errorf("classifyFirstLine(%q) = %q want %q", in, got, want)
		}
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZZZ"); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
