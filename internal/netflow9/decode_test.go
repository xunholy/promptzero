package netflow9

import (
	"strings"
	"testing"
)

func TestDecode_HeaderOnlyNoFlowSets(t *testing.T) {
	// Header with Count=0.
	in := "0009 0000 00000001 60000000 00000001 00000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 9 {
		t.Errorf("version: %d", r.Version)
	}
	if r.Count != 0 {
		t.Errorf("count: %d", r.Count)
	}
	if r.SequenceNumber != 1 || r.SourceID != 1 {
		t.Errorf("ids: seq=%d src=%d", r.SequenceNumber, r.SourceID)
	}
	if r.ExportTimestampISO == "" {
		t.Errorf("expected ISO timestamp")
	}
}

func TestDecode_TemplateFlowSet_FiveFields(t *testing.T) {
	// Template ID 256, 5 fields:
	//   IPV4_SRC_ADDR (8, len 4)
	//   IPV4_DST_ADDR (12, len 4)
	//   L4_SRC_PORT (7, len 2)
	//   L4_DST_PORT (11, len 2)
	//   PROTOCOL (4, len 1)
	in := "0009 0001 00000001 60000000 00000001 00000001" +
		"0000 001C 0100 0005" +
		"00080004 000C0004 00070002 000B0002 00040001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.FlowSets) != 1 {
		t.Fatalf("flowsets: %d", len(r.FlowSets))
	}
	fs := r.FlowSets[0]
	if fs.Kind != "Template FlowSet" {
		t.Errorf("kind: %q", fs.Kind)
	}
	if len(fs.Templates) != 1 {
		t.Fatalf("templates: %d", len(fs.Templates))
	}
	tmpl := fs.Templates[0]
	if tmpl.TemplateID != 256 || tmpl.FieldCount != 5 {
		t.Errorf("template header: %+v", tmpl)
	}
	if tmpl.RecordSize != 13 {
		t.Errorf("record size: %d (expected 13)", tmpl.RecordSize)
	}
	names := []string{}
	for _, f := range tmpl.Fields {
		names = append(names, f.TypeName)
	}
	want := []string{"IPV4_SRC_ADDR", "IPV4_DST_ADDR",
		"L4_SRC_PORT", "L4_DST_PORT", "PROTOCOL"}
	for i, n := range want {
		if names[i] != n {
			t.Errorf("field %d: got %q want %q", i, names[i], n)
		}
	}
}

func TestDecode_DataFlowSet_RawHex(t *testing.T) {
	// Template + Data FlowSet referencing template 256.
	// Data body = 1 record (13 bytes payload + 3 pad = 16
	// bytes body, length = 4 + 16 = 20 = 0x14).
	in := "0009 0002 00000001 60000000 00000001 00000001" +
		"0000 001C 0100 0005 00080004 000C0004 00070002 000B0002 00040001" +
		"0100 0014 C0A80101 0A000001 0050 D431 06 000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.FlowSets) != 2 {
		t.Fatalf("flowsets: %d", len(r.FlowSets))
	}
	data := r.FlowSets[1]
	if data.Kind != "Data FlowSet" {
		t.Errorf("kind: %q", data.Kind)
	}
	if data.DataFlowSet == nil {
		t.Fatal("Data FlowSet body nil")
	}
	if data.DataFlowSet.ReferencedTemplateID != 256 {
		t.Errorf("template ref: %d", data.DataFlowSet.ReferencedTemplateID)
	}
	// Body should contain the 16 bytes of records + padding.
	if data.DataFlowSet.BodyBytes != 16 {
		t.Errorf("body bytes: %d", data.DataFlowSet.BodyBytes)
	}
}

func TestDecode_OptionsTemplate(t *testing.T) {
	// FlowSet ID 1 (Options Template).
	in := "0009 0001 00000001 60000000 00000001 00000001" +
		"0001 0010 0101 0002 00220004 00230004"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	fs := r.FlowSets[0]
	if fs.Kind != "Options Template FlowSet" {
		t.Errorf("kind: %q", fs.Kind)
	}
	if len(fs.OptionTemplates) != 1 {
		t.Fatalf("option templates: %d", len(fs.OptionTemplates))
	}
}

func TestDecode_MultipleTemplatesInOneFlowSet(t *testing.T) {
	// Two back-to-back templates in one FlowSet.
	// Template 256 with 2 fields + Template 257 with 1 field.
	// Body = (4 + 8) + (4 + 4) = 20.
	// FlowSet = 4 + 20 = 24 = 0x18.
	in := "0009 0001 00000001 60000000 00000001 00000001" +
		"0000 0018 0100 0002 00080004 000C0004" +
		"0101 0001 00040001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tmpls := r.FlowSets[0].Templates
	if len(tmpls) != 2 {
		t.Fatalf("templates: %d", len(tmpls))
	}
	if tmpls[0].TemplateID != 256 || tmpls[1].TemplateID != 257 {
		t.Errorf("template IDs: %d / %d",
			tmpls[0].TemplateID, tmpls[1].TemplateID)
	}
}

func TestDecode_FieldTypeNameSpotCheck(t *testing.T) {
	cases := map[int]string{
		1:   "IN_BYTES",
		2:   "IN_PKTS",
		4:   "PROTOCOL",
		6:   "TCP_FLAGS",
		7:   "L4_SRC_PORT",
		8:   "IPV4_SRC_ADDR",
		12:  "IPV4_DST_ADDR",
		15:  "IPV4_NEXT_HOP",
		21:  "LAST_SWITCHED",
		22:  "FIRST_SWITCHED",
		27:  "IPV6_SRC_ADDR",
		28:  "IPV6_DST_ADDR",
		56:  "SRC_MAC",
		61:  "DIRECTION",
		136: "FLOW_END_REASON",
	}
	for k, v := range cases {
		if got := fieldTypeName(k); got != v {
			t.Errorf("fieldTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedFieldType(t *testing.T) {
	if got := fieldTypeName(9999); !strings.Contains(got, "uncatalogued") {
		t.Errorf("expected uncatalogued field type, got %q", got)
	}
}

func TestDecode_FlowSetKindTable(t *testing.T) {
	cases := map[uint16]string{
		0:   "Template FlowSet",
		1:   "Options Template FlowSet",
		256: "Data FlowSet",
		300: "Data FlowSet",
	}
	for k, v := range cases {
		if got := flowSetKind(k); got != v {
			t.Errorf("flowSetKind(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UnsupportedVersion(t *testing.T) {
	// Version 5 (NetFlow v5, not handled by this Spec).
	in := "0005 0000 00000001 60000000 00000000 00000001 0001 0000"
	_, err := Decode(in)
	if err == nil {
		t.Fatal("expected error for v5")
	}
}

func TestDecode_TruncatedFlowSet_Note(t *testing.T) {
	// FlowSet declares Length=100 but only 10 bytes available.
	in := "0009 0001 00000001 60000000 00000001 00000001" +
		"0000 0064 0100 0002"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected truncation note")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "0009 000",
		"short":   "0009 0000",
		"bad hex": "ZZ09 0000 00000001 60000000 00000000 00000001",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
