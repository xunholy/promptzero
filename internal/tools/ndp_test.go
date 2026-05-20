package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNDPDecodeHandler_RouterAdvertisement pins a canonical RA
// carrying a SLAAC prefix + RDNSS option (the mitm6 attack
// surface).
func TestNDPDecodeHandler_RouterAdvertisement(t *testing.T) {
	in := "86 00 1234 " +
		"40 C0 0708 00000000 00000000 " +
		"01 01 001122334455 " +
		"03 04 40 C0 FFFFFFFF FFFFFFFF 00000000 20010DB8000000000000000000000000 " +
		"19 03 0000 00000E10 20010DB8000000000000000000000001"
	out, err := ndpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Router_Advertisement"`,
		`"cur_hop_limit": 64`,
		`"ra_managed": true`,
		`"ra_other": true`,
		`"router_lifetime_seconds": 1800`,
		`"link_layer_address": "00:11:22:33:44:55"`,
		`"type_name": "Prefix_Information"`,
		`"prefix_length": 64`,
		`"prefix_on_link": true`,
		`"type_name": "RDNSS"`,
		`"lifetime_seconds": 3600`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNDPDecodeHandler_NeighborSolicitation pins an NS — IPv6
// equivalent of ARP.
func TestNDPDecodeHandler_NeighborSolicitation(t *testing.T) {
	in := "87 00 ABCD 00000000 " +
		"20010DB80000000000000000000000AB " +
		"01 01 AABBCCDDEEFF"
	out, err := ndpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Neighbor_Solicitation"`,
		`"target_address": "2001:db8::ab"`,
		`"link_layer_address": "AA:BB:CC:DD:EE:FF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNDPDecodeHandler_NeighborAdvertisement pins an NA with
// R/S/O flags.
func TestNDPDecodeHandler_NeighborAdvertisement(t *testing.T) {
	in := "88 00 1234 E0 000000 " +
		"20010DB80000000000000000000000AB " +
		"02 01 112233445566"
	out, err := ndpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Neighbor_Advertisement"`,
		`"na_router": true`,
		`"na_solicited": true`,
		`"na_override": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestNDPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ndpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
