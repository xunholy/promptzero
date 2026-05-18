package tools

import (
	"context"
	"strings"
	"testing"
)

// TestBluetoothCoDDecodeHandler_SmartPhone confirms the
// handler decodes a Smart Phone CoD through to JSON.
func TestBluetoothCoDDecodeHandler_SmartPhone(t *testing.T) {
	out, err := bluetoothCoDDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "5A020C",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"major_class_name": "Phone"`) {
		t.Errorf("expected Phone in output:\n%s", out)
	}
	if !strings.Contains(out, `"minor_class_name": "Smart phone"`) {
		t.Errorf("expected Smart phone:\n%s", out)
	}
	if !strings.Contains(out, "Telephony") {
		t.Errorf("expected Telephony service class:\n%s", out)
	}
}

// TestBluetoothCoDDecodeHandler_Laptop confirms a Laptop CoD
// surfaces with the right names.
func TestBluetoothCoDDecodeHandler_Laptop(t *testing.T) {
	out, err := bluetoothCoDDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "0x12010C",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"minor_class_name": "Laptop"`) {
		t.Errorf("expected Laptop:\n%s", out)
	}
}

func TestBluetoothCoDDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := bluetoothCoDDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
