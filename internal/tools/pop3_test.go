package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func pop3Hexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestPOP3DecodeHandler_Banner pins a canonical +OK greeting.
func TestPOP3DecodeHandler_Banner(t *testing.T) {
	msg := "+OK Dovecot (Ubuntu) ready.\r\n"
	out, err := pop3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": pop3Hexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Response"`,
		`"status": "+OK"`,
		`"status_text": "Dovecot (Ubuntu) ready."`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPOP3DecodeHandler_USERCommand pins the USER command.
func TestPOP3DecodeHandler_USERCommand(t *testing.T) {
	msg := "USER admin\r\n"
	out, err := pop3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": pop3Hexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Command"`,
		`"verb": "USER"`,
		`"argument": "admin"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPOP3DecodeHandler_CAPAMultiline pins CAPA multi-line
// response — the STLS + SASL mechanism enumeration goldmine.
func TestPOP3DecodeHandler_CAPAMultiline(t *testing.T) {
	msg := "+OK Capability list follows\r\n" +
		"TOP\r\n" +
		"USER\r\n" +
		"SASL CRAM-MD5 PLAIN LOGIN\r\n" +
		"UIDL\r\n" +
		"STLS\r\n" +
		".\r\n"
	out, err := pop3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": pop3Hexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"status": "+OK"`,
		`"TOP"`,
		`"SASL CRAM-MD5 PLAIN LOGIN"`,
		`"STLS"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPOP3DecodeHandler_AuthFailed pins the canonical brute-
// force feedback signal.
func TestPOP3DecodeHandler_AuthFailed(t *testing.T) {
	msg := "-ERR Authentication failed.\r\n"
	out, err := pop3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": pop3Hexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"status": "-ERR"`,
		`"status_text": "Authentication failed."`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPOP3DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := pop3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
