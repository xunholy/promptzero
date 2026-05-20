package tools

import (
	"context"
	"strings"
	"testing"
)

// TestLACPDecodeHandler_FullPDU pins a canonical LACPDU with
// Actor, Partner, Collector, and Terminator TLVs.
func TestLACPDecodeHandler_FullPDU(t *testing.T) {
	in := "01 01" +
		"01 14 0064 001122334455 0001 0080 0001 3D 000000" +
		"02 14 0064 AABBCCDDEEFF 0001 0080 0001 3D 000000" +
		"03 10 8000 000000000000000000000000" +
		"00 00"
	out, err := lacpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"subtype_name": "LACP"`,
		`"type_name": "Actor Information"`,
		`"system_id": "00:11:22:33:44:55"`,
		`"type_name": "Partner Information"`,
		`"system_id": "aa:bb:cc:dd:ee:ff"`,
		`"type_name": "Collector Information"`,
		`"max_delay": 32768`,
		`"type_name": "Terminator"`,
		`"lacp_activity": true`,
		`"synchronization": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLACPDecodeHandler_StateAllSet pins all 8 state bits set.
func TestLACPDecodeHandler_StateAllSet(t *testing.T) {
	in := "01 01 01 14 0064 001122334455 0001 0080 0001 FF 000000 00 00"
	out, err := lacpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"lacp_activity": true`,
		`"lacp_timeout_short": true`,
		`"aggregation": true`,
		`"synchronization": true`,
		`"collecting": true`,
		`"distributing": true`,
		`"defaulted": true`,
		`"expired": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLACPDecodeHandler_MarkerNote pins the Marker subtype
// fallback note.
func TestLACPDecodeHandler_MarkerNote(t *testing.T) {
	in := "02 01"
	out, err := lacpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"subtype_name": "Marker"`) {
		t.Errorf("expected Marker subtype:\n%s", out)
	}
}

func TestLACPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := lacpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
