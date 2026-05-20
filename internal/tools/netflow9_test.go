package tools

import (
	"context"
	"strings"
	"testing"
)

// TestNetFlowV9DecodeHandler_TemplateAndData pins a canonical
// NetFlow v9 packet with Template + Data FlowSet.
func TestNetFlowV9DecodeHandler_TemplateAndData(t *testing.T) {
	in := "0009 0002 00000001 60000000 00000001 00000001" +
		"0000 001C 0100 0005 00080004 000C0004 00070002 000B0002 00040001" +
		"0100 0014 C0A80101 0A000001 0050 D431 06 000000"
	out, err := netflowV9DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 9`,
		`"count": 2`,
		`"sequence_number": 1`,
		`"source_id": 1`,
		`"kind": "Template FlowSet"`,
		`"template_id": 256`,
		`"type_name": "IPV4_SRC_ADDR"`,
		`"type_name": "L4_DST_PORT"`,
		`"type_name": "PROTOCOL"`,
		`"record_size_bytes": 13`,
		`"kind": "Data FlowSet"`,
		`"referenced_template_id": 256`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestNetFlowV9DecodeHandler_OptionsTemplate pins decoding
// of the Options Template FlowSet (ID = 1).
func TestNetFlowV9DecodeHandler_OptionsTemplate(t *testing.T) {
	in := "0009 0001 00000001 60000000 00000001 00000001" +
		"0001 0010 0101 0002 00220004 00230004"
	out, err := netflowV9DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"kind": "Options Template FlowSet"`) {
		t.Errorf("expected Options Template kind:\n%s", out)
	}
	if !strings.Contains(out, `"template_id": 257`) {
		t.Errorf("expected template ID 257:\n%s", out)
	}
}

// TestNetFlowV9DecodeHandler_HeaderOnly pins zero-FlowSet
// packets.
func TestNetFlowV9DecodeHandler_HeaderOnly(t *testing.T) {
	in := "0009 0000 00000001 60000000 00000001 00000001"
	out, err := netflowV9DecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"count": 0`) {
		t.Errorf("expected count 0:\n%s", out)
	}
}

func TestNetFlowV9DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := netflowV9DecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
