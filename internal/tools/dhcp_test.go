package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// TestDHCPPacketDecodeHandler_DiscoverPin builds a minimal
// DHCPDISCOVER packet and pins it through the handler.
func TestDHCPPacketDecodeHandler_DiscoverPin(t *testing.T) {
	pkt := make([]byte, 240)
	pkt[0] = 0x01 // BOOTREQUEST
	pkt[1] = 0x01 // Ethernet
	pkt[2] = 0x06 // hlen
	binary.BigEndian.PutUint32(pkt[4:8], 0xCAFEBABE)
	copy(pkt[28:34], []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC})
	binary.BigEndian.PutUint32(pkt[236:240], 0x63825363)
	// Append options 53 (DISCOVER) + End (255)
	pkt = append(pkt, 53, 1, 1, 255)

	out, err := dhcpPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex.EncodeToString(pkt),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"op_name": "BOOTREQUEST"`) {
		t.Errorf("expected BOOTREQUEST:\n%s", out)
	}
	if !strings.Contains(out, `"message_type": "DISCOVER"`) {
		t.Errorf("expected DISCOVER:\n%s", out)
	}
	if !strings.Contains(out, `"client_hw_mac": "12:34:56:78:9a:bc"`) {
		t.Errorf("expected MAC in output:\n%s", out)
	}
}

func TestDHCPPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := dhcpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestDHCPPacketDecodeHandler_RejectsTooShort(t *testing.T) {
	_, err := dhcpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": "01 01 06 00"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
