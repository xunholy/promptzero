package tools

import (
	"context"
	"strings"
	"testing"
)

// TestOSPFPacketDecodeHandler_Hello pins a canonical Hello
// packet through the Spec handler.
func TestOSPFPacketDecodeHandler_Hello(t *testing.T) {
	in := "02 01 0030 C0A80101 00000000 0000 0000 0000000000000000" +
		"FFFFFF00 000A 02 01 00000028 C0A80101 C0A80102 C0A80102"
	out, err := ospfPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Hello"`,
		`"router_id": "192.168.1.1"`,
		`"area_id": "0.0.0.0"`,
		`"network_mask": "255.255.255.0"`,
		`"hello_interval_seconds": 10`,
		`"router_dead_interval_seconds": 40`,
		`"designated_router": "192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestOSPFPacketDecodeHandler_DBD pins a DBD packet with an
// LSA Header.
func TestOSPFPacketDecodeHandler_DBD(t *testing.T) {
	in := "02 02 0034 C0A80101 00000000 0000 0000 0000000000000000" +
		"05DC 02 07 12345678" +
		"0E10 02 01 C0A80101 C0A80101 80000001 ABCD 0030"
	out, err := ospfPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"type_name": "Database Description (DBD)"`) {
		t.Errorf("expected DBD type:\n%s", out)
	}
	if !strings.Contains(out, `"ls_type_name": "Router LSA"`) {
		t.Errorf("expected Router LSA name:\n%s", out)
	}
}

// TestOSPFPacketDecodeHandler_LSAck pins an LSAck packet.
func TestOSPFPacketDecodeHandler_LSAck(t *testing.T) {
	in := "02 05 002C C0A80101 00000000 0000 0000 0000000000000000" +
		"0E10 02 01 C0A80101 C0A80101 80000001 ABCD 0030"
	out, err := ospfPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "Link State Acknowledgment (LSAck)") {
		t.Errorf("expected LSAck:\n%s", out)
	}
}

func TestOSPFPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ospfPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
