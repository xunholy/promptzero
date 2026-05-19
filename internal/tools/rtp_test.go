package tools

import (
	"context"
	"strings"
	"testing"
)

// TestRTPPacketDecodeHandler_RTP_PCMU pins a canonical minimal
// RTP PCMU packet through the Spec handler.
func TestRTPPacketDecodeHandler_RTP_PCMU(t *testing.T) {
	in := "8000 1234 00000000 DEADBEEF AABBCCDD"
	out, err := rtpPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": in,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"kind": "rtp"`) {
		t.Errorf("expected kind rtp:\n%s", out)
	}
	if !strings.Contains(out, `"payload_type_name": "PCMU/8000/1"`) {
		t.Errorf("expected PCMU name:\n%s", out)
	}
	if !strings.Contains(out, `"sequence_number": 4660`) {
		t.Errorf("expected seq 0x1234:\n%s", out)
	}
}

// TestRTPPacketDecodeHandler_RTCP_Composite pins an SR+SDES
// composite RTCP datagram.
func TestRTPPacketDecodeHandler_RTCP_Composite(t *testing.T) {
	sr := "81C8 000C DEADBEEF 83AA7E80 00000000 000003E8 " +
		"0000000A 00000280 " +
		"CAFEBABE 00000005 0000004A 00000005 12345678 00000001"
	sdes := "81CA 0003 ABCDEF01 0104 75736572 0000"
	out, err := rtpPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": sr + sdes,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"kind": "rtcp"`) {
		t.Errorf("expected kind rtcp:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "SR (Sender Report)"`) {
		t.Errorf("expected SR:\n%s", out)
	}
	if !strings.Contains(out, `"text": "user"`) {
		t.Errorf("expected CNAME 'user':\n%s", out)
	}
}

func TestRTPPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := rtpPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestRTPPacketDecodeHandler_RejectsBadVersion(t *testing.T) {
	_, err := rtpPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "40000000 00000000 00000000",
	})
	if err == nil {
		t.Fatal("want error for version 1")
	}
}
