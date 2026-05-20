package smtp

import (
	"encoding/hex"
	"strings"
	"testing"
)

// hexify converts an ASCII SMTP message to hex for feeding
// the hex-input decoder.
func hexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestDecodeBannerResponse pins the canonical 220 banner.
func TestDecodeBannerResponse(t *testing.T) {
	msg := "220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindResponse {
		t.Errorf("kind: got %q want Response", r.Kind)
	}
	if r.StatusCode != 220 {
		t.Errorf("status: got %d want 220", r.StatusCode)
	}
	if r.StatusCategory != "Success" {
		t.Errorf("category: got %q want Success", r.StatusCategory)
	}
	if r.FinalLineText != "mail.example.com ESMTP Postfix (Debian/GNU)" {
		t.Errorf("finalLine: got %q", r.FinalLineText)
	}
}

// TestDecodeEHLOCommand pins the EHLO greeting command.
func TestDecodeEHLOCommand(t *testing.T) {
	msg := "EHLO mail.attacker.com\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Kind != KindCommand {
		t.Errorf("kind: got %q want Command", r.Kind)
	}
	if r.Verb != "EHLO" {
		t.Errorf("verb: got %q want EHLO", r.Verb)
	}
	if r.Argument != "mail.attacker.com" {
		t.Errorf("argument: got %q", r.Argument)
	}
}

// TestDecodeEHLOMultilineResponse pins the canonical multi-
// line EHLO response that lists supported extensions
// (STARTTLS / AUTH / SIZE etc.).
func TestDecodeEHLOMultilineResponse(t *testing.T) {
	msg := "250-mail.example.com Hello\r\n" +
		"250-SIZE 35882577\r\n" +
		"250-8BITMIME\r\n" +
		"250-STARTTLS\r\n" +
		"250-AUTH LOGIN PLAIN CRAM-MD5\r\n" +
		"250-ENHANCEDSTATUSCODES\r\n" +
		"250 HELP\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StatusCode != 250 {
		t.Errorf("status: got %d want 250", r.StatusCode)
	}
	if len(r.Lines) != 7 {
		t.Errorf("lines: got %d want 7", len(r.Lines))
	}
	if r.FinalLineText != "HELP" {
		t.Errorf("finalLineText: got %q want HELP", r.FinalLineText)
	}
	wantExt := []string{"SIZE 35882577", "8BITMIME", "STARTTLS",
		"AUTH LOGIN PLAIN CRAM-MD5", "ENHANCEDSTATUSCODES", "HELP"}
	if len(r.EHLOExtensions) != len(wantExt) {
		t.Errorf("ehlo extensions count: got %d want %d",
			len(r.EHLOExtensions), len(wantExt))
	}
	for i, w := range wantExt {
		if i < len(r.EHLOExtensions) && r.EHLOExtensions[i] != w {
			t.Errorf("ext[%d]: got %q want %q", i, r.EHLOExtensions[i], w)
		}
	}
}

// TestDecodeMAILFROMCommand pins the canonical MAIL FROM
// command — the open-relay-probe entry point.
func TestDecodeMAILFROMCommand(t *testing.T) {
	msg := "MAIL FROM:<attacker@evil.com>\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "MAIL" {
		t.Errorf("verb: got %q want MAIL", r.Verb)
	}
	if r.Argument != "FROM:<attacker@evil.com>" {
		t.Errorf("argument: got %q", r.Argument)
	}
}

// TestDecodeVRFYCommand pins the user-enumeration target.
func TestDecodeVRFYCommand(t *testing.T) {
	msg := "VRFY admin\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "VRFY" {
		t.Errorf("verb: got %q want VRFY", r.Verb)
	}
	if r.Argument != "admin" {
		t.Errorf("argument: got %q want admin", r.Argument)
	}
}

// TestDecodeSTARTTLSCommand pins STARTTLS — the TLS upgrade
// trigger.
func TestDecodeSTARTTLSCommand(t *testing.T) {
	msg := "STARTTLS\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Verb != "STARTTLS" {
		t.Errorf("verb: got %q want STARTTLS", r.Verb)
	}
	if r.Argument != "" {
		t.Errorf("argument: should be empty, got %q", r.Argument)
	}
}

// TestDecodeAuthFailedResponse pins a 535 Authentication
// Failed response — the canonical brute-force feedback signal.
func TestDecodeAuthFailedResponse(t *testing.T) {
	msg := "535 5.7.8 Authentication failed: bad credentials\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StatusCode != 535 {
		t.Errorf("status: got %d want 535", r.StatusCode)
	}
	if r.StatusCategory != "Permanent_Error" {
		t.Errorf("category: got %q want Permanent_Error", r.StatusCategory)
	}
	if !strings.Contains(r.FinalLineText, "Authentication failed") {
		t.Errorf("finalLine: got %q", r.FinalLineText)
	}
}

// TestDecode354DataIntermediate pins the 354 Start mail input
// response — the only Intermediate-category code.
func TestDecode354DataIntermediate(t *testing.T) {
	msg := "354 End data with <CR><LF>.<CR><LF>\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StatusCode != 354 {
		t.Errorf("status: got %d want 354", r.StatusCode)
	}
	if r.StatusCategory != "Intermediate" {
		t.Errorf("category: got %q want Intermediate", r.StatusCategory)
	}
}

// TestDecode550MailboxUnavailable pins a 550 mailbox-not-found
// response — the VRFY user-enumeration negative signal.
func TestDecode550MailboxUnavailable(t *testing.T) {
	msg := "550 5.1.1 <bogus@target.com>: Recipient address rejected: User unknown\r\n"
	r, err := Decode(hexify(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StatusCode != 550 || r.StatusCategory != "Permanent_Error" {
		t.Errorf("status: got %d/%q want 550/Permanent_Error",
			r.StatusCode, r.StatusCategory)
	}
}

// TestStatusCategoryTable covers every documented category.
func TestStatusCategoryTable(t *testing.T) {
	cases := map[int]string{
		220: "Success",
		354: "Intermediate",
		421: "Transient_Error",
		550: "Permanent_Error",
	}
	for k, v := range cases {
		if got := statusCategory(k); got != v {
			t.Errorf("statusCategory(%d) = %q want %q", k, got, v)
		}
	}
}

// TestClassifyFirstLine covers each catalogued kind.
func TestClassifyFirstLine(t *testing.T) {
	cases := map[string]MessageKind{
		"220 banner": KindResponse,
		"EHLO host":  KindCommand,
		"helo host":  KindCommand,
		"QUIT":       KindCommand,
		"":           KindUnknown,
		"~?invalid":  KindUnknown,
	}
	for in, want := range cases {
		if got := classifyFirstLine(in); got != want {
			t.Errorf("classifyFirstLine(%q) = %q want %q", in, got, want)
		}
	}
}

// TestParseResponseLineFinalDelimiter pins the
// `<code><space>` vs `<code><hyphen>` final-line distinction
// per RFC 5321 §4.2.1.
func TestParseResponseLineFinalDelimiter(t *testing.T) {
	if _, final, _ := parseResponseLine("250 OK"); !final {
		t.Errorf("250<space> should be final")
	}
	if _, final, _ := parseResponseLine("250-Continued"); final {
		t.Errorf("250<hyphen> should NOT be final")
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
