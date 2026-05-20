package tools

import (
	"context"
	"strings"
	"testing"
)

// TestPIMDecodeHandler_Hello pins a canonical PIMv2 Hello
// with Holdtime + DR Priority + Generation ID.
func TestPIMDecodeHandler_Hello(t *testing.T) {
	in := "20 00 ABCD" +
		"0001 0002 0069" +
		"0013 0004 00000001" +
		"0014 0004 DEADBEEF"
	out, err := pimDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Hello"`,
		`"holdtime_seconds": 105`,
		`"dr_priority": 1`,
		`"generation_id": 3735928559`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPIMDecodeHandler_JoinPrune pins a Join/Prune carrying
// one Group with one Joined source.
func TestPIMDecodeHandler_JoinPrune(t *testing.T) {
	in := "23 00 ABCD" +
		"01 00 C0A80101" +
		"00 01 00B4" +
		"01 00 00 20 EF010203" +
		"0001 0000" +
		"01 00 04 20 0A000001"
	out, err := pimDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Join/Prune"`,
		`"hold_time_seconds": 180`,
		`"address": "192.168.1.1"`,
		`"address": "239.1.2.3"`,
		`"address": "10.0.0.1"`,
		`"s_bit_sparse": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestPIMDecodeHandler_Assert pins an Assert with metric +
// RPT bit decoding.
func TestPIMDecodeHandler_Assert(t *testing.T) {
	in := "25 00 ABCD" +
		"01 00 00 20 EF010203" +
		"01 00 C0A80101" +
		"0000006E 0000000A"
	out, err := pimDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "Assert"`,
		`"metric_preference": 110`,
		`"metric": 10`,
		`"rpt_bit": false`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestPIMDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := pimDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
