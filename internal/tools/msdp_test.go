package tools

import (
	"context"
	"strings"
	"testing"
)

// TestMSDPDecodeHandler_SourceActive pins a canonical
// IPv4 Source-Active TLV.
func TestMSDPDecodeHandler_SourceActive(t *testing.T) {
	in := "01 0014 01 C0A80101 000000 20 EF010203 0A000001"
	out, err := msdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "IPv4 Source-Active"`,
		`"entry_count": 1`,
		`"rp_address": "192.168.1.1"`,
		`"sprefix_length": 32`,
		`"group_address": "239.1.2.3"`,
		`"source_address": "10.0.0.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMSDPDecodeHandler_KeepaliveAndSA pins multiple TLVs
// in one buffer (Keepalive + SA Response).
func TestMSDPDecodeHandler_KeepaliveAndSA(t *testing.T) {
	in := "04 0003" +
		"03 0014 01 C0A80101 000000 20 EF010203 0A000001"
	out, err := msdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Keepalive"`,
		`"type_name": "IPv4 SA Response"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMSDPDecodeHandler_Notification pins error code decoding.
func TestMSDPDecodeHandler_Notification(t *testing.T) {
	in := "06 0005 04 00"
	out, err := msdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Notification"`,
		`"error_code": 4`,
		`"error_code_name": "Hold Timer Expired"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestMSDPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := msdpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
