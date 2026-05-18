package tools

import (
	"context"
	"strings"
	"testing"
)

// TestBluetoothGATTUUIDLookupHandler_BatteryService confirms
// the handler resolves the Battery service through to JSON.
func TestBluetoothGATTUUIDLookupHandler_BatteryService(t *testing.T) {
	out, err := bluetoothGATTUUIDLookupHandler(context.Background(), nil, map[string]any{
		"uuid": "180F",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"name": "Battery"`) {
		t.Errorf("expected Battery name:\n%s", out)
	}
	if !strings.Contains(out, `"category": "Service"`) {
		t.Errorf("expected Service category:\n%s", out)
	}
}

// TestBluetoothGATTUUIDLookupHandler_128Bit confirms 128-bit
// UUID with SIG base pattern resolves correctly.
func TestBluetoothGATTUUIDLookupHandler_128Bit(t *testing.T) {
	out, err := bluetoothGATTUUIDLookupHandler(context.Background(), nil, map[string]any{
		"uuid": "00002A19-0000-1000-8000-00805F9B34FB",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"name": "Battery Level"`) {
		t.Errorf("expected Battery Level characteristic:\n%s", out)
	}
}

// TestBluetoothGATTUUIDLookupHandler_VendorSpecific confirms
// a non-base-pattern 128-bit UUID is flagged as vendor-specific.
func TestBluetoothGATTUUIDLookupHandler_VendorSpecific(t *testing.T) {
	out, err := bluetoothGATTUUIDLookupHandler(context.Background(), nil, map[string]any{
		"uuid": "6E400001-B5A3-F393-E0A9-E50E24DCCA9E",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"vendor_specific": true`) {
		t.Errorf("expected vendor_specific true:\n%s", out)
	}
}

func TestBluetoothGATTUUIDLookupHandler_RejectsEmpty(t *testing.T) {
	_, err := bluetoothGATTUUIDLookupHandler(context.Background(), nil, map[string]any{"uuid": ""})
	if err == nil {
		t.Fatal("want error for empty uuid")
	}
}
