package tools

import (
	"context"
	"strings"
	"testing"
)

// TestVRRPDecodeHandler_V2Advertisement pins a canonical
// VRRPv2 Advertisement through the Spec handler.
func TestVRRPDecodeHandler_V2Advertisement(t *testing.T) {
	in := "21 0A 64 01 00 01 ABCD C0A80101"
	out, err := vrrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 2`,
		`"type_name": "Advertisement"`,
		`"vrid": 10`,
		`"priority": 100`,
		`"auth_type_name": "No Authentication"`,
		`"adver_int_seconds": 1`,
		`"address_family": "IPv4"`,
		`"192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestVRRPDecodeHandler_V3IPv6 pins a VRRPv3 IPv6 packet.
func TestVRRPDecodeHandler_V3IPv6(t *testing.T) {
	in := "31 01 64 01 0064 ABCD FE80000000000000 0000000000000001"
	out, err := vrrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"address_family": "IPv6"`) {
		t.Errorf("expected IPv6:\n%s", out)
	}
	if !strings.Contains(out, "fe80::1") {
		t.Errorf("expected fe80::1:\n%s", out)
	}
	if !strings.Contains(out, `"max_adver_interval_ms": 1000`) {
		t.Errorf("expected MaxAdverInt 1000 ms:\n%s", out)
	}
}

// TestVRRPDecodeHandler_PriorityOwner pins the 255 IP-owner
// priority semantic note.
func TestVRRPDecodeHandler_PriorityOwner(t *testing.T) {
	in := "31 0A FF 01 0064 ABCD C0A80101"
	out, err := vrrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "IP address owner") {
		t.Errorf("expected IP-owner note:\n%s", out)
	}
}

func TestVRRPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := vrrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
