package tools

import (
	"context"
	"strings"
	"testing"
)

// TestICMPPacketDecodeHandler_V4EchoRequest pins a canonical
// ICMPv4 Echo Request through the Spec handler.
func TestICMPPacketDecodeHandler_V4EchoRequest(t *testing.T) {
	in := "08 00 ABCD 1234 0001 6869"
	out, err := icmpPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"version": "v4"`) {
		t.Errorf("expected v4:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "Echo Request"`) {
		t.Errorf("expected Echo Request:\n%s", out)
	}
	if !strings.Contains(out, `"identifier": 4660`) { // 0x1234
		t.Errorf("expected identifier 0x1234:\n%s", out)
	}
}

// TestICMPPacketDecodeHandler_V6NeighborSolicit pins ICMPv6 NS
// with target address fe80::1.
func TestICMPPacketDecodeHandler_V6NeighborSolicit(t *testing.T) {
	target := "FE80000000000000000000000000 0001"
	opt := "01 01 AABBCCDDEEFF"
	in := "87 00 0000 00000000 " + target + opt
	out, err := icmpPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"version": "v6"`) {
		t.Errorf("expected v6:\n%s", out)
	}
	if !strings.Contains(out, `"target_address": "fe80::1"`) {
		t.Errorf("expected target fe80::1:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "Source Link-Layer Address"`) {
		t.Errorf("expected NDP option name:\n%s", out)
	}
}

// TestICMPPacketDecodeHandler_VersionHint exercises the v6 hint
// path for an ambiguous type (Packet Too Big shares numeric code
// with v4 Source Quench).
func TestICMPPacketDecodeHandler_VersionHint(t *testing.T) {
	in := "02 00 0000 000005DC " + strings.Repeat("00", 40)
	out, err := icmpPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in, "version": "v6"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"type_name": "Packet Too Big"`) {
		t.Errorf("expected Packet Too Big with v6 hint:\n%s", out)
	}
	if !strings.Contains(out, `"mtu": 1500`) {
		t.Errorf("expected MTU 1500:\n%s", out)
	}
}

func TestICMPPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := icmpPacketDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
