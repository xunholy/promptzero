package tools

import (
	"context"
	"strings"
	"testing"
)

// makeWGBytes returns a hex string of the given length filled
// with byte b.
func makeWGBytes(n int, b byte) string {
	const digits = "0123456789ABCDEF"
	out := make([]byte, n*2)
	for i := 0; i < n; i++ {
		out[i*2] = digits[b>>4]
		out[i*2+1] = digits[b&0x0F]
	}
	return string(out)
}

// TestWireguardPacketDecodeHandler_Initiation pins a fully-
// formed handshake initiation (148 bytes).
func TestWireguardPacketDecodeHandler_Initiation(t *testing.T) {
	in := "01" + "000000" + "44332211" +
		makeWGBytes(32, 0xAA) +
		makeWGBytes(48, 0xBB) +
		makeWGBytes(28, 0xCC) +
		makeWGBytes(16, 0xDD) +
		makeWGBytes(16, 0x00)
	out, err := wireguardPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"message_type_name": "Handshake Initiation"`) {
		t.Errorf("expected Initiation:\n%s", out)
	}
	if !strings.Contains(out, `"mac2_zero": true`) {
		t.Errorf("expected mac2_zero true:\n%s", out)
	}
}

// TestWireguardPacketDecodeHandler_Transport pins a Transport
// Data packet.
func TestWireguardPacketDecodeHandler_Transport(t *testing.T) {
	in := "04" + "000000" + "BEBAFECA" +
		"3930000000000000" +
		makeWGBytes(32, 0x77) +
		makeWGBytes(16, 0x99)
	out, err := wireguardPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"message_type_name": "Transport Data"`) {
		t.Errorf("expected Transport Data:\n%s", out)
	}
	if !strings.Contains(out, `"counter": 12345`) {
		t.Errorf("expected counter 12345:\n%s", out)
	}
}

func TestWireguardPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := wireguardPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestWireguardPacketDecodeHandler_RejectsUnknownType(t *testing.T) {
	_, err := wireguardPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "05" + "000000" + makeWGBytes(50, 0xAA)})
	if err == nil {
		t.Fatal("want error for unknown message type")
	}
}
