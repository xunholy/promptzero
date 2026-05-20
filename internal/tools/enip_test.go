package tools

import (
	"context"
	"strings"
	"testing"
)

// TestENIPDecodeHandler_RegisterSession pins a canonical
// RegisterSession command.
func TestENIPDecodeHandler_RegisterSession(t *testing.T) {
	in := "65 00 04 00 00 00 00 00 00 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00 " +
		"01 00 00 00"
	out, err := enipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "RegisterSession"`,
		`"status_name": "Success"`,
		`"payload_hex": "01000000"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestENIPDecodeHandler_SendRRDataCIPRequest pins a SendRRData
// command carrying a CIP Get_Attribute_Single request.
func TestENIPDecodeHandler_SendRRDataCIPRequest(t *testing.T) {
	in := "6F 00 16 00 04 03 02 01 00 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00 " +
		"00 00 00 00 05 00 02 00 " +
		"00 00 00 00 " +
		"B2 00 0A 00 " +
		"0E 03 20 04 24 01 30 01 AA BB"
	out, err := enipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"command_name": "SendRRData"`,
		`"timeout": 5`,
		`"item_count": 2`,
		`"type_name": "Null"`,
		`"type_name": "Unconnected_Data"`,
		`"service_name": "Get_Attribute_Single"`,
		`"is_response": false`,
		`"path_hex": "200424013001"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestENIPDecodeHandler_CIPResponseAttributeNotSupported pins a
// CIP response with a named general status.
func TestENIPDecodeHandler_CIPResponseAttributeNotSupported(t *testing.T) {
	in := "6F 00 12 00 04 03 02 01 00 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00 " +
		"00 00 00 00 05 00 02 00 " +
		"00 00 00 00 " +
		"B2 00 04 00 8E 00 14 00"
	out, err := enipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_response": true`,
		`"service_name": "Get_Attribute_Single"`,
		`"general_status_name": "Attribute_Not_Supported"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestENIPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := enipDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
