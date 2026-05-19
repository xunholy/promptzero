package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// TestNTPPacketDecodeHandler_ClientRequest builds a typical
// NTPv4 client request and pins it through the Spec handler.
func TestNTPPacketDecodeHandler_ClientRequest(t *testing.T) {
	pkt := make([]byte, 48)
	pkt[0] = (0 << 6) | (4 << 3) | 3 // LI=0 | VN=4 | Mode=3 (client)
	pkt[1] = 0                       // Stratum
	pkt[2] = 10                      // Poll = 1024s
	precision := int8(-6)
	pkt[3] = byte(precision)
	// Transmit time = arbitrary non-zero (2023-11-14)
	binary.BigEndian.PutUint32(pkt[40:44], 2208988800+1700000000)

	out, err := ntpPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex.EncodeToString(pkt),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"version_number": 4`) {
		t.Errorf("expected version_number 4:\n%s", out)
	}
	if !strings.Contains(out, `"mode_name": "Client"`) {
		t.Errorf("expected mode_name Client:\n%s", out)
	}
	if !strings.Contains(out, `"poll_interval_sec": 1024`) {
		t.Errorf("expected poll_interval_sec 1024:\n%s", out)
	}
	if !strings.Contains(out, `"precision_log2": -6`) {
		t.Errorf("expected precision_log2 -6:\n%s", out)
	}
	if !strings.Contains(out, `"unix_seconds": 1700000000`) {
		t.Errorf("expected unix_seconds 1700000000:\n%s", out)
	}
}

func TestNTPPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ntpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestNTPPacketDecodeHandler_RejectsTooShort(t *testing.T) {
	_, err := ntpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": "00 01 02 03"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
