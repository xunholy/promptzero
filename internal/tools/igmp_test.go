package tools

import (
	"context"
	"strings"
	"testing"
)

// TestIGMPDecodeHandler_IGMPv2GeneralQuery pins the canonical
// IGMPv2 General Query (Type 0x11, Group 0.0.0.0).
func TestIGMPDecodeHandler_IGMPv2GeneralQuery(t *testing.T) {
	in := "11 64 ABCD 00000000"
	out, err := igmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 2`,
		`"type_name": "Membership Query"`,
		`"group_address": "0.0.0.0"`,
		`"max_resp_centiseconds": 100`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIGMPDecodeHandler_IGMPv3Report pins an IGMPv3 Membership
// Report with one Group Record.
func TestIGMPDecodeHandler_IGMPv3Report(t *testing.T) {
	in := "22 00 ABCD 0000 0001 01 00 0001 E0010203 C0A80101"
	out, err := igmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "IGMPv3 Membership Report"`,
		`"number_of_group_records": 1`,
		`"record_type_name": "MODE_IS_INCLUDE"`,
		`"multicast_address": "224.1.2.3"`,
		`"192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIGMPDecodeHandler_IGMPv3QueryWithSources pins an IGMPv3
// Group-and-Source Specific Query.
func TestIGMPDecodeHandler_IGMPv3QueryWithSources(t *testing.T) {
	in := "11 64 ABCD E0010203 02 7D 0002 C0A80101 C0A80102"
	out, err := igmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 3`,
		`"qrv_querier_robustness": 2`,
		`"number_of_sources": 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestIGMPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := igmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
