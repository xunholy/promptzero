package tools

import (
	"context"
	"strings"
	"testing"
)

// TestGOOSEDecodeHandler_TripMessage pins a canonical TRIP GOOSE
// with full PDU fields.
func TestGOOSEDecodeHandler_TripMessage(t *testing.T) {
	in := "0001 005F 0000 0000 " +
		"61 81 54 " +
		"80 12 50524F542F4C4C4E3024474F246763623031 " +
		"81 02 0FA0 " +
		"82 0E 50524F542F4C4C4E302444533031 " +
		"83 06 545249505F41 " +
		"84 08 654E89B8 000000 00 " +
		"85 01 05 86 01 0C 87 01 00 " +
		"88 01 01 89 01 00 8A 01 02 " +
		"AB 06 83 01 FF 83 01 00"
	out, err := gooseDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"appid": 1`,
		`"gocb_ref": "PROT/LLN0$GO$gcb01"`,
		`"time_allowed_to_live_ms": 4000`,
		`"dat_set": "PROT/LLN0$DS01"`,
		`"go_id": "TRIP_A"`,
		`"st_num": 5`,
		`"sq_num": 12`,
		`"conf_rev": 1`,
		`"num_dat_set_entries": 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGOOSEDecodeHandler_Minimal pins the minimal-field GOOSE.
func TestGOOSEDecodeHandler_Minimal(t *testing.T) {
	in := "0001 0018 0000 0000 " +
		"61 0E " +
		"85 01 01 86 01 00 87 01 FF " +
		"AB 03 83 01 FF"
	out, err := gooseDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"st_num": 1`,
		`"sq_num": 0`,
		`"test": true`,
		`"all_data_hex": "8301FF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGOOSEDecodeHandler_SecurityTrailer pins surfacing of bytes
// past the PDU end.
func TestGOOSEDecodeHandler_SecurityTrailer(t *testing.T) {
	in := "0001 0013 0000 0000 " +
		"61 06 85 01 01 86 01 00 " +
		"DEAD BEEF"
	out, err := gooseDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"security_trailer_hex": "DEADBEEF"`) {
		t.Errorf("expected security trailer in output:\n%s", out)
	}
}

func TestGOOSEDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := gooseDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
