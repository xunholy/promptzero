package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

func imapHexify(s string) string {
	return hex.EncodeToString([]byte(s))
}

// TestIMAPDecodeHandler_Banner pins the * OK greeting.
func TestIMAPDecodeHandler_Banner(t *testing.T) {
	msg := "* OK Dovecot (Ubuntu) ready.\r\n"
	out, err := imapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": imapHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Untagged_Response"`,
		`"untagged_type": "OK"`,
		`"untagged_data": "Dovecot (Ubuntu) ready."`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIMAPDecodeHandler_LoginCommand pins the cleartext
// credentials-disclosure command.
func TestIMAPDecodeHandler_LoginCommand(t *testing.T) {
	msg := "a001 LOGIN admin hunter2\r\n"
	out, err := imapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": imapHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Command"`,
		`"tag": "a001"`,
		`"verb": "LOGIN"`,
		`"verb_name": "LOGIN (cleartext credentials!)"`,
		`"argument": "admin hunter2"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIMAPDecodeHandler_TaggedNOResponse pins the brute-force
// feedback signal.
func TestIMAPDecodeHandler_TaggedNOResponse(t *testing.T) {
	msg := "a002 NO Authentication failed.\r\n"
	out, err := imapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": imapHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Tagged_Response"`,
		`"tag": "a002"`,
		`"status": "NO"`,
		`"status_text": "Authentication failed."`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIMAPDecodeHandler_AuthenticateContinuation pins the SASL
// + server challenge.
func TestIMAPDecodeHandler_AuthenticateContinuation(t *testing.T) {
	msg := "+ UGFzc3dvcmQ6\r\n"
	out, err := imapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": imapHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Continuation"`,
		`"continuation_prompt": "UGFzc3dvcmQ6"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIMAPDecodeHandler_Capability pins the CAPABILITY
// response — the canonical pre-auth enumeration step.
func TestIMAPDecodeHandler_Capability(t *testing.T) {
	msg := "* CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5 IDLE NAMESPACE\r\n"
	out, err := imapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": imapHexify(msg)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"untagged_type": "CAPABILITY"`,
		`STARTTLS`,
		`AUTH=PLAIN`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestIMAPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := imapDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
