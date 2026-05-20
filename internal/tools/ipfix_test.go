package tools

import (
	"context"
	"strings"
	"testing"
)

// TestIPFIXDecodeHandler_TemplateAndData pins a canonical
// IPFIX message with Template + Data Set.
func TestIPFIXDecodeHandler_TemplateAndData(t *testing.T) {
	in := "000A 0040 60000000 00000001 00000001" +
		"0002 001C 0100 0005 00080004 000C0004 00070002 000B0002 00040001" +
		"0100 0014 C0A80101 0A000001 0050 D431 06 000000"
	out, err := ipfixDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"version": 10`,
		`"observation_domain_id": 1`,
		`"kind": "Template Set"`,
		`"template_id": 256`,
		`"type_name": "sourceIPv4Address"`,
		`"type_name": "destinationIPv4Address"`,
		`"type_name": "protocolIdentifier"`,
		`"record_size_bytes": 13`,
		`"kind": "Data Set"`,
		`"referenced_template_id": 256`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIPFIXDecodeHandler_EnterpriseField pins decoding of an
// enterprise-extended Field Specifier (8 bytes instead of 4).
func TestIPFIXDecodeHandler_EnterpriseField(t *testing.T) {
	in := "000A 0020 60000000 00000001 00000001" +
		"0002 0010 0100 0001 8001 0004 00000009"
	out, err := ipfixDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_enterprise": true`,
		`"enterprise_number": 9`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestIPFIXDecodeHandler_OptionsTemplate pins scope/option
// split for Options Template Sets.
func TestIPFIXDecodeHandler_OptionsTemplate(t *testing.T) {
	in := "000A 0022 60000000 00000001 00000001" +
		"0003 0012 0100 0002 0001 008A0004 00220004"
	out, err := ipfixDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"kind": "Options Template Set"`,
		`"scope_field_count": 1`,
		`"observationPointId"`,
		`"samplingInterval"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestIPFIXDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ipfixDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
