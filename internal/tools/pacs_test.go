package tools

import (
	"context"
	"strings"
	"testing"
)

// TestRFIDPACSDecodeHandler_H10301Bits pins the canonical H10301
// 26-bit FC=123 CN=45678 vector through the Spec handler.
func TestRFIDPACSDecodeHandler_H10301Bits(t *testing.T) {
	out, err := rfidPACSDecodeHandler(context.Background(), nil, map[string]any{
		"bits": "10111101110110010011011101",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"format": "HID H10301 26-bit"`) {
		t.Errorf("expected H10301 format:\n%s", out)
	}
	if !strings.Contains(out, `"facility_code": 123`) {
		t.Errorf("expected FC 123:\n%s", out)
	}
	if !strings.Contains(out, `"card_number": 45678`) {
		t.Errorf("expected CN 45678:\n%s", out)
	}
	if !strings.Contains(out, `"parity_valid": true`) {
		t.Errorf("expected parity_valid true:\n%s", out)
	}
}

// TestRFIDPACSDecodeHandler_H10301Hex pins the same vector via
// the hex+bit_length input path.
func TestRFIDPACSDecodeHandler_H10301Hex(t *testing.T) {
	out, err := rfidPACSDecodeHandler(context.Background(), nil, map[string]any{
		"hex":        "BDD93740",
		"bit_length": 26,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"card_number": 45678`) {
		t.Errorf("expected CN 45678:\n%s", out)
	}
}

func TestRFIDPACSDecodeHandler_RejectsMissingInputs(t *testing.T) {
	_, err := rfidPACSDecodeHandler(context.Background(), nil, map[string]any{})
	if err == nil {
		t.Fatal("want error when neither bits nor hex provided")
	}
}

func TestRFIDPACSDecodeHandler_RejectsHexWithoutLength(t *testing.T) {
	_, err := rfidPACSDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "BDD93740",
	})
	if err == nil {
		t.Fatal("want error when hex provided without bit_length")
	}
}
