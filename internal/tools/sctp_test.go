package tools

import (
	"context"
	"strings"
	"testing"
)

// TestSCTPDecodeHandler_INIT pins a canonical INIT chunk
// with IPv4 address parameter.
func TestSCTPDecodeHandler_INIT(t *testing.T) {
	in := "04D2 162E 00000000 12345678" +
		"01 00 001C CAFEBABE 00010000 0001 0001 00000064" +
		"0005 0008 C0A80101"
	out, err := sctpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"source_port": 1234`,
		`"destination_port": 5678`,
		`"type_name": "INIT"`,
		`"initiate_tag": 3405691582`,
		`"advertised_receiver_window_credit": 65536`,
		`"initial_tsn": 100`,
		`"type_name": "IPv4 Address"`,
		`"ipv4_address": "192.168.1.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSCTPDecodeHandler_DATADiameter pins a DATA chunk
// carrying Diameter (PPID 46).
func TestSCTPDecodeHandler_DATADiameter(t *testing.T) {
	in := "04D2 162E DEADBEEF 12345678" +
		"00 03 0014 00000001 0000 0000 0000002E 01020304"
	out, err := sctpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "DATA"`,
		`"payload_protocol_identifier": 46`,
		`"payload_protocol_identifier_name": "Diameter (cleartext)"`,
		`"flag_beginning_fragment": true`,
		`"flag_ending_fragment": true`,
		`"user_data_hex": "01020304"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestSCTPDecodeHandler_SACK pins a SACK with gap + duplicate.
func TestSCTPDecodeHandler_SACK(t *testing.T) {
	in := "04D2 162E DEADBEEF 12345678" +
		"03 00 0018 00000064 00010000 0001 0001" +
		"0002 0005 00000063"
	out, err := sctpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"type_name": "SACK"`,
		`"cumulative_tsn_ack": 100`,
		`"num_gap_ack_blocks": 1`,
		`"num_duplicate_tsns": 1`,
		`"start_offset": 2`,
		`"end_offset": 5`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestSCTPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := sctpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
