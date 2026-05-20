package tools

import (
	"context"
	"strings"
	"testing"
)

// TestTACACSPlusDecodeHandler_AuthStart pins a canonical
// AUTH START packet with UNENCRYPTED_FLAG.
func TestTACACSPlusDecodeHandler_AuthStart(t *testing.T) {
	in := "C0 01 01 01 12345678 00000018" +
		"01 0F 02 01 05 04 07 00" +
		"61646D696E 74747930 312E322E332E34"
	out, err := tacacsPlusDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"packet_type_name": "Authentication"`,
		`"flag_unencrypted": true`,
		`"action_name": "LOGIN"`,
		`"authentication_type_name": "PAP"`,
		`"service_name": "LOGIN"`,
		`"user": "admin"`,
		`"port": "tty0"`,
		`"remote_address": "1.2.3.4"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestTACACSPlusDecodeHandler_AcctRequestStart pins an ACCT
// REQUEST with START flag + named argument.
func TestTACACSPlusDecodeHandler_AcctRequestStart(t *testing.T) {
	in := "C0 03 01 01 12345678 00000024" +
		"02 06 0F 01 01 05 04 07 01 0A" +
		"61646D696E 74747930 312E322E332E34" +
		"7461736B5F69643D3432"
	out, err := tacacsPlusDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"packet_type_name": "Accounting"`,
		`"flag_start": true`,
		`"flag_stop": false`,
		`"task_id=42"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestTACACSPlusDecodeHandler_EncryptedNoKey pins the
// encrypted-body fallback path (no key → opaque hex + note).
func TestTACACSPlusDecodeHandler_EncryptedNoKey(t *testing.T) {
	in := "C0 01 01 00 12345678 00000018" +
		"112233445566778899AABBCCDDEEFF00112233445566778899"
	out, err := tacacsPlusDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"body_encrypted": true`,
		`"flag_unencrypted": false`,
		`encrypted`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestTACACSPlusDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := tacacsPlusDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
