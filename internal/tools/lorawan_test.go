package tools

import (
	"context"
	"strings"
	"testing"
)

// TestLoRaWANDecodeHandler_DataUpHappyPath sends a minimal
// Unconfirmed Data Up frame and confirms the Spec handler
// returns JSON with the documented top-level shape.
func TestLoRaWANDecodeHandler_DataUpHappyPath(t *testing.T) {
	out, err := lorawanDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "40 04030201 80 0100 01 AABBCC 11223344",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"mtype_name": "Unconfirmed Data Up"`) {
		t.Errorf("expected mtype_name in output:\n%s", out)
	}
	if !strings.Contains(out, `"dev_addr_hex": "01020304"`) {
		t.Errorf("expected dev_addr_hex 01020304:\n%s", out)
	}
	if !strings.Contains(out, `"mic_hex": "11223344"`) {
		t.Errorf("expected mic_hex 11223344:\n%s", out)
	}
}

// TestLoRaWANDecodeHandler_JoinRequest confirms the Join Request
// decode round-trips through the handler.
func TestLoRaWANDecodeHandler_JoinRequest(t *testing.T) {
	out, err := lorawanDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "00 0807060504030201 100F0E0D0C0B0A09 7856 11223344",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"join_eui_hex": "0102030405060708"`) {
		t.Errorf("expected join_eui_hex:\n%s", out)
	}
	if !strings.Contains(out, `"dev_eui_hex": "090A0B0C0D0E0F10"`) {
		t.Errorf("expected dev_eui_hex:\n%s", out)
	}
}

func TestLoRaWANDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := lorawanDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
