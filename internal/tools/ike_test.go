package tools

import (
	"context"
	"strings"
	"testing"
)

// TestIKEV2DecodeHandler_HeaderOnly pins a canonical IKE_SA
// _INIT header with no payloads.
func TestIKEV2DecodeHandler_HeaderOnly(t *testing.T) {
	in := "1122334455667788 0000000000000000" +
		"21 20 22 08 00000000 0000001C"
	out, err := ikeV2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"initiator_spi_hex": "0x1122334455667788"`,
		`"exchange_type_name": "IKE_SA_INIT"`,
		`"flag_initiator": true`,
		`"flag_response": false`,
		`"version_major": 2`,
		`"first_payload_name": "SA (Security Association)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIKEV2DecodeHandler_SKEncrypted pins the SK payload
// surfacing with encryption note.
func TestIKEV2DecodeHandler_SKEncrypted(t *testing.T) {
	in := "1122334455667788 AABBCCDDEEFF0011" +
		"2E 20 23 08 00000001 0000002C" +
		"00 00 0010 DEADBEEFDEADBEEFDEADBEEF"
	out, err := ikeV2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"exchange_type_name": "IKE_AUTH"`,
		`"type_name": "SK (Encrypted and Authenticated)"`,
		`"encrypted_bytes": 12`,
		`SK_e/SK_a keys`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIKEV2DecodeHandler_AuthFailedNotify pins an Error-class
// Notify payload.
func TestIKEV2DecodeHandler_AuthFailedNotify(t *testing.T) {
	in := "1122334455667788 AABBCCDDEEFF0011" +
		"29 20 25 20 00000002 00000024" +
		"00 00 0008 00 00 0018"
	out, err := ikeV2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"exchange_type_name": "INFORMATIONAL"`,
		`"notify_message_name": "AUTHENTICATION_FAILED"`,
		`"notify_message_class": "Error"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestIKEV2DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ikeV2DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
