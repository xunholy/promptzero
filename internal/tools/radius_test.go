package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// TestRadiusPacketDecodeHandler_AccessRequest builds an
// Access-Request and pins it through the Spec handler.
func TestRadiusPacketDecodeHandler_AccessRequest(t *testing.T) {
	hdr := make([]byte, 20)
	hdr[0] = 1
	hdr[1] = 0x42
	// User-Name (1) = "alice"
	attrs := append([]byte{1, 7}, []byte("alice")...)
	// NAS-IP-Address (4) = 192.168.1.1
	ipAttr := []byte{4, 6}
	ipAttr = append(ipAttr, net.ParseIP("192.168.1.1").To4()...)
	attrs = append(attrs, ipAttr...)
	totalLen := 20 + len(attrs)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(totalLen))
	pkt := append(hdr, attrs...)

	out, err := radiusPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex.EncodeToString(pkt),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"code_name": "Access-Request"`) {
		t.Errorf("expected Access-Request:\n%s", out)
	}
	if !strings.Contains(out, `"name": "User-Name"`) {
		t.Errorf("expected User-Name:\n%s", out)
	}
	if !strings.Contains(out, `"string": "alice"`) {
		t.Errorf("expected alice:\n%s", out)
	}
	if !strings.Contains(out, `"ipv4": "192.168.1.1"`) {
		t.Errorf("expected IPv4:\n%s", out)
	}
}

func TestRadiusPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := radiusPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestRadiusPacketDecodeHandler_RejectsTooShort(t *testing.T) {
	_, err := radiusPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": "01 02 03 04"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
