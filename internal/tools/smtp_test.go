package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func smtpHexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestSMTPDecodeHandler_Banner pins a 220 banner — the
// canonical MTA fingerprinting surface.
func TestSMTPDecodeHandler_Banner(t *testing.T) {
	msg := "220 mail.example.com ESMTP Postfix (Debian/GNU)\r\n"
	out, err := smtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": smtpHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Response"`,
		`"status_code": 220`,
		`"status_category": "Success"`,
		`"final_line_text": "mail.example.com ESMTP Postfix (Debian/GNU)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSMTPDecodeHandler_EHLOMultiline pins the EHLO multi-line
// response that exposes the supported extensions.
func TestSMTPDecodeHandler_EHLOMultiline(t *testing.T) {
	msg := "250-mail.example.com Hello\r\n" +
		"250-STARTTLS\r\n" +
		"250-AUTH LOGIN PLAIN\r\n" +
		"250 HELP\r\n"
	out, err := smtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": smtpHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"status_code": 250`,
		`"final_line_text": "HELP"`,
		`"STARTTLS"`,
		`"AUTH LOGIN PLAIN"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSMTPDecodeHandler_VRFYCommand pins the canonical user-
// enumeration target.
func TestSMTPDecodeHandler_VRFYCommand(t *testing.T) {
	msg := "VRFY admin\r\n"
	out, err := smtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": smtpHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Command"`,
		`"verb": "VRFY"`,
		`"argument": "admin"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSMTPDecodeHandler_AuthFailed pins the 535 Authentication
// Failed response — the canonical brute-force feedback.
func TestSMTPDecodeHandler_AuthFailed(t *testing.T) {
	msg := "535 5.7.8 Authentication failed: bad credentials\r\n"
	out, err := smtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": smtpHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"status_code": 535`,
		`"status_category": "Permanent_Error"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestSMTPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := smtpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
