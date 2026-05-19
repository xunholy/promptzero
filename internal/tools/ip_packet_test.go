package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// TestIPPacketDecodeHandler_IPv4TCPSyn builds a minimal IPv4
// TCP SYN packet and pins it through the Spec handler.
func TestIPPacketDecodeHandler_IPv4TCPSyn(t *testing.T) {
	ipHdr := make([]byte, 20)
	ipHdr[0] = 0x45 // version=4, IHL=5
	binary.BigEndian.PutUint16(ipHdr[2:4], 40)
	ipHdr[8] = 64
	ipHdr[9] = 6 // TCP
	copy(ipHdr[12:16], net.ParseIP("10.0.0.1").To4())
	copy(ipHdr[16:20], net.ParseIP("10.0.0.2").To4())
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 5 << 4 // data offset = 5
	tcp[13] = 0x02   // SYN
	pkt := append(ipHdr, tcp...)

	out, err := ipPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex.EncodeToString(pkt),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"version": 4`) {
		t.Errorf("expected version 4:\n%s", out)
	}
	if !strings.Contains(out, `"protocol_name": "TCP"`) {
		t.Errorf("expected TCP protocol:\n%s", out)
	}
	if !strings.Contains(out, `"flag_syn": true`) {
		t.Errorf("expected flag_syn true:\n%s", out)
	}
	if !strings.Contains(out, `"source_ip": "10.0.0.1"`) {
		t.Errorf("expected source_ip:\n%s", out)
	}
}

func TestIPPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ipPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestIPPacketDecodeHandler_RejectsBadVersion(t *testing.T) {
	_, err := ipPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": "70 00 00 00"})
	if err == nil {
		t.Fatal("want error for unknown version")
	}
}
