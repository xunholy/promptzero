package tools

import (
	"context"
	"strings"
	"testing"
)

const bgpMarker = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"

// TestBGPMessageDecodeHandler_Keepalive pins a canonical
// 19-byte KEEPALIVE through the Spec handler.
func TestBGPMessageDecodeHandler_Keepalive(t *testing.T) {
	in := bgpMarker + "001304"
	out, err := bgpMessageDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"type_name": "KEEPALIVE"`) {
		t.Errorf("expected KEEPALIVE:\n%s", out)
	}
	if !strings.Contains(out, `"marker_valid": true`) {
		t.Errorf("expected marker_valid true:\n%s", out)
	}
}

// TestBGPMessageDecodeHandler_OpenWithMPBGP pins an OPEN
// message with MP-BGP capability.
func TestBGPMessageDecodeHandler_OpenWithMPBGP(t *testing.T) {
	in := bgpMarker + "002501" +
		"04FC0000B4C0A8010108020601040001 0001"
	out, err := bgpMessageDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"my_as": 64512`) {
		t.Errorf("expected my_as 64512:\n%s", out)
	}
	if !strings.Contains(out, `"hold_time_seconds": 180`) {
		t.Errorf("expected hold_time 180:\n%s", out)
	}
	if !strings.Contains(out, `"bgp_identifier": "192.168.1.1"`) {
		t.Errorf("expected BGP identifier:\n%s", out)
	}
	if !strings.Contains(out, "MP-BGP") {
		t.Errorf("expected MP-BGP capability:\n%s", out)
	}
}

// TestBGPMessageDecodeHandler_NotificationCease pins a
// NOTIFICATION (Cease, Admin Shutdown).
func TestBGPMessageDecodeHandler_NotificationCease(t *testing.T) {
	in := bgpMarker + "00150306" + "02"
	out, err := bgpMessageDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"error_code_name": "Cease (RFC 4486)"`) {
		t.Errorf("expected Cease error code:\n%s", out)
	}
	if !strings.Contains(out, `"error_subcode_name": "Administrative Shutdown"`) {
		t.Errorf("expected Admin Shutdown subcode:\n%s", out)
	}
}

func TestBGPMessageDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := bgpMessageDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
