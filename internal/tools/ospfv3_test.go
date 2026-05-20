package tools

import (
	"context"
	"strings"
	"testing"
)

// TestOSPFv3DecodeHandler_Hello pins a canonical Hello packet
// with one neighbor.
func TestOSPFv3DecodeHandler_Hello(t *testing.T) {
	in := "03 01 0028 01010101 00000000 ABCD 00 00" +
		"00000001 01 000013 000A 0028 01010101 00000000 02020202"
	out, err := ospfv3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Hello"`,
		`"router_id": "1.1.1.1"`,
		`"interface_id": 1`,
		`"hello_interval_seconds": 10`,
		`"router_dead_interval_seconds": 40`,
		`"designated_router_id": "1.1.1.1"`,
		`"2.2.2.2"`,
		`"v6": true`,
		`"e_external": true`,
		`"r_router": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestOSPFv3DecodeHandler_DBD pins a Database Description
// packet with I/M/MS flags set.
func TestOSPFv3DecodeHandler_DBD(t *testing.T) {
	in := "03 02 001C 01010101 00000000 ABCD 00 00" +
		"00 000013 05DC 00 07 00000001"
	out, err := ospfv3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Database Description"`,
		`"interface_mtu": 1500`,
		`"flag_init": true`,
		`"flag_more": true`,
		`"flag_master_slave": true`,
		`"dd_sequence_number": 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestOSPFv3DecodeHandler_LSU pins an LSU with one
// Router-LSA header.
func TestOSPFv3DecodeHandler_LSU(t *testing.T) {
	in := "03 04 0028 01010101 00000000 ABCD 00 00" +
		"00000001" +
		"0001 2001 00000000 01010101 80000001 CDEF 0014"
	out, err := ospfv3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Link State Update"`,
		`"number_of_lsas": 1`,
		`"ls_type_name": "Router-LSA"`,
		`"flooding_scope_name": "Area"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestOSPFv3DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ospfv3DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
