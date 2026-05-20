package tools

import (
	"context"
	"strings"
	"testing"
)

// TestIEC104DecodeHandler_Interrogation pins a canonical general
// interrogation command (C_IC_NA_1, COT = act).
func TestIEC104DecodeHandler_Interrogation(t *testing.T) {
	in := "68 0E 02 00 0A 00 64 01 06 00 01 00 00 00 00 14"
	out, err := iec104DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"frame_format": "I"`,
		`"send_seq": 1`,
		`"receive_seq": 5`,
		`"type_name": "C_IC_NA_1"`,
		`"cot_name": "act"`,
		`"common_address": 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIEC104DecodeHandler_SFormatAck pins a supervisory ack.
func TestIEC104DecodeHandler_SFormatAck(t *testing.T) {
	in := "68 04 01 00 40 00"
	out, err := iec104DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"frame_format": "S"`,
		`"receive_seq": 32`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIEC104DecodeHandler_UFormatSTARTDT pins STARTDT_act link
// control.
func TestIEC104DecodeHandler_UFormatSTARTDT(t *testing.T) {
	in := "68 04 07 00 00 00"
	out, err := iec104DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"frame_format": "U"`,
		`"u_function_bits": "STARTDT_act"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestIEC104DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := iec104DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
