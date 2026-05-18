package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNRF24PacketDecodeHandler_HappyPath confirms the Spec
// handler decodes a minimal NRF24 packet through to JSON.
func TestNRF24PacketDecodeHandler_HappyPath(t *testing.T) {
	out, err := nrf24PacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "AA BB CC DD EE 10 01 02 03 04 55 66",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"address_hex": "AABBCCDDEE"`) {
		t.Errorf("expected address in output:\n%s", out)
	}
	if !strings.Contains(out, `"payload_length": 4`) {
		t.Errorf("expected payload_length 4:\n%s", out)
	}
}

// TestNRF24PacketDecodeHandler_LogitechRecognition confirms
// Logitech Unifying HID Boot Keyboard reports get the
// structured Logitech view.
func TestNRF24PacketDecodeHandler_LogitechRecognition(t *testing.T) {
	out, err := nrf24PacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "AA BB CC DD EE 1C 01 40 02 00 00 04 00 12 34",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"report_name": "HID Boot Keyboard report"`) {
		t.Errorf("expected Logitech HID report name:\n%s", out)
	}
}

// TestNRF24PacketDecodeHandler_AddressLengthOption confirms
// the address_length option round-trips.
func TestNRF24PacketDecodeHandler_AddressLengthOption(t *testing.T) {
	out, err := nrf24PacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex":            "AA BB CC 08 01 02 FF EE",
		"address_length": float64(3),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"address_length": 3`) {
		t.Errorf("expected address_length 3:\n%s", out)
	}
}

func TestNRF24PacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := nrf24PacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
