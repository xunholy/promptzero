package tools

import (
	"context"
	"strings"
	"testing"
)

// TestZWaveDecodeHandler_BasicSet pins the canonical BASIC SET
// command (Z-Wave "turn on light").
func TestZWaveDecodeHandler_BasicSet(t *testing.T) {
	in := "C0FFEE01 01 21 35 0D 05 20 01 FF AA"
	out, err := zwaveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"home_id_hex": "0xC0FFEE01"`,
		`"source_node_id": 1`,
		`"header_type_name": "Singlecast"`,
		`"ack_requested": true`,
		`"destination_node_id": 5`,
		`"command_class_name": "BASIC"`,
		`"command": 1`,
		`"parameters_hex": "FF"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestZWaveDecodeHandler_DoorLock pins a DOOR_LOCK command —
// the canonical Yale Z-Wave lock target.
func TestZWaveDecodeHandler_DoorLock(t *testing.T) {
	in := "11223344 01 41 00 0D 02 62 01 FF EE"
	out, err := zwaveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"command_class_name": "DOOR_LOCK"`) {
		t.Errorf("expected DOOR_LOCK in output:\n%s", out)
	}
}

// TestZWaveDecodeHandler_SecurityS2 pins a SECURITY_2 container.
func TestZWaveDecodeHandler_SecurityS2(t *testing.T) {
	in := "11223344 02 41 10 10 03 9F 03 AA BB CC DD EE FF 00 CC"
	out, err := zwaveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"command_class_name": "SECURITY_2"`) {
		t.Errorf("expected SECURITY_2 in output:\n%s", out)
	}
}

func TestZWaveDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := zwaveDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
