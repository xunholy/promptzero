package tools

import (
	"context"
	"strings"
	"testing"
)

// TestDNSPacketDecodeHandler_QueryA pins a hand-crafted DNS
// query for example.com A IN through the Spec handler.
//
// Wire bytes:
//
//	1234 0100 0001 0000 0000 0000   header
//	07 65 78 61 6d 70 6c 65 03 63 6f 6d 00   "example.com"
//	0001 0001                       QTYPE A, QCLASS IN
func TestDNSPacketDecodeHandler_QueryA(t *testing.T) {
	hex := "1234 0100 0001 0000 0000 0000 " +
		"07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 " +
		"00 01 00 01"
	out, err := dnsPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": hex})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"transaction_id": 4660`) {
		t.Errorf("expected transaction_id 4660 (0x1234):\n%s", out)
	}
	if !strings.Contains(out, `"qr_name": "query"`) {
		t.Errorf("expected qr_name 'query':\n%s", out)
	}
	if !strings.Contains(out, `"name": "example.com"`) {
		t.Errorf("expected name 'example.com':\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "A"`) {
		t.Errorf("expected type_name 'A':\n%s", out)
	}
}

func TestDNSPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := dnsPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestDNSPacketDecodeHandler_RejectsTooShort(t *testing.T) {
	_, err := dnsPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": "12 34"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
