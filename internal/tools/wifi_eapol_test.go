package tools

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"
)

// makeEAPOLFrame builds a minimal EAPOL-Key frame with the
// given Key Information field for tool-handler tests.
func makeEAPOLFrame(t *testing.T, keyInfo uint16) string {
	t.Helper()
	out := make([]byte, 99)
	out[0] = 0x02
	out[1] = 0x03
	out[2] = 0x00
	out[3] = 0x5F // body length = 95
	out[4] = 0x02
	out[5] = byte(keyInfo >> 8)
	out[6] = byte(keyInfo & 0xFF)
	out[7] = 0x00
	out[8] = 0x10
	for i := 17; i < 49; i++ {
		out[i] = 0xFE
	}
	for i := 81; i < 97; i++ {
		out[i] = 0xAA
	}
	return hex.EncodeToString(out)
}

// TestWifiEAPOLDecodeHandler_M1HappyPath sends a synthesised M1
// frame and confirms the Spec handler decodes it through to
// JSON with the M1 message identification.
func TestWifiEAPOLDecodeHandler_M1HappyPath(t *testing.T) {
	out, err := wifiEAPOLDecodeHandler(context.Background(), nil, map[string]any{
		"hex": makeEAPOLFrame(t, 0x008A),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"handshake_message": "M1"`) {
		t.Errorf("expected handshake_message M1 in output:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "EAPOL-Key"`) {
		t.Errorf("expected type_name EAPOL-Key in output:\n%s", out)
	}
}

// TestWifiEAPOLDecodeHandler_M3 confirms M3 identification.
func TestWifiEAPOLDecodeHandler_M3(t *testing.T) {
	out, err := wifiEAPOLDecodeHandler(context.Background(), nil, map[string]any{
		"hex": makeEAPOLFrame(t, 0x03CA),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"handshake_message": "M3"`) {
		t.Errorf("expected M3:\n%s", out)
	}
	if !strings.Contains(out, `"install": true`) {
		t.Errorf("expected install=true:\n%s", out)
	}
}

func TestWifiEAPOLDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := wifiEAPOLDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
