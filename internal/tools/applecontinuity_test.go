package tools

import (
	"context"
	"strings"
	"testing"
)

// TestBLEContinuityClassifyHandler_NearbyInfo pins the full
// AD-record envelope path with a Nearby Info TLV.
func TestBLEContinuityClassifyHandler_NearbyInfo(t *testing.T) {
	in := "0A FF 4C00 10 05 83 00 ABCDEF"
	out, err := bleContinuityClassifyHandler(context.Background(), nil, map[string]any{
		"hex": in,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"type_name": "Nearby Info"`) {
		t.Errorf("expected Nearby Info type:\n%s", out)
	}
	if !strings.Contains(out, `"action_name": "iOS Lock Screen"`) {
		t.Errorf("expected iOS Lock Screen action:\n%s", out)
	}
	if !strings.Contains(out, `"outer_format": "ad_record"`) {
		t.Errorf("expected ad_record envelope:\n%s", out)
	}
}

// TestBLEContinuityClassifyHandler_IBeacon pins iBeacon
// decoding with the standard UUID formatting.
func TestBLEContinuityClassifyHandler_IBeacon(t *testing.T) {
	in := "02 15 F8E8A3A35B1A4D4E8B8E1F1F1F1F1F1F 0064 00C8 C6"
	out, err := bleContinuityClassifyHandler(context.Background(), nil, map[string]any{
		"hex": in,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"uuid": "F8E8A3A3-5B1A-4D4E-8B8E-1F1F1F1F1F1F"`) {
		t.Errorf("expected UUID:\n%s", out)
	}
	if !strings.Contains(out, `"major": 100`) {
		t.Errorf("expected major 100:\n%s", out)
	}
	if !strings.Contains(out, `"tx_power_dbm": -58`) {
		t.Errorf("expected TxPower -58:\n%s", out)
	}
}

func TestBLEContinuityClassifyHandler_RejectsEmpty(t *testing.T) {
	_, err := bleContinuityClassifyHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestBLEContinuityClassifyHandler_RejectsBadEnvelope(t *testing.T) {
	_, err := bleContinuityClassifyHandler(context.Background(), nil,
		map[string]any{"hex": "DEADBEEF"})
	if err == nil {
		t.Fatal("want error for non-Apple envelope")
	}
}
