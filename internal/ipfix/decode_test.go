package ipfix

import (
	"strings"
	"testing"
)

func TestDecode_HeaderOnlyNoSets(t *testing.T) {
	// 16-byte header with no Sets (declared length = 16).
	in := "000A 0010 60000000 00000001 00000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 10 {
		t.Errorf("version: %d", r.Version)
	}
	if r.MessageLength != 16 {
		t.Errorf("length: %d", r.MessageLength)
	}
	if r.SequenceNumber != 1 || r.ObservationDomainID != 1 {
		t.Errorf("ids: %+v", r)
	}
	if r.ExportTimestampISO == "" {
		t.Errorf("expected ISO timestamp")
	}
}

func TestDecode_TemplateSet_FiveFields(t *testing.T) {
	// Template ID 256 with 5 standard IEs.
	// Length = 16 (header) + 28 (template) = 44 = 0x2C.
	in := "000A 002C 60000000 00000001 00000001" +
		"0002 001C 0100 0005" +
		"00080004 000C0004 00070002 000B0002 00040001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Sets) != 1 {
		t.Fatalf("sets: %d", len(r.Sets))
	}
	s := r.Sets[0]
	if s.Kind != "Template Set" {
		t.Errorf("kind: %q", s.Kind)
	}
	if len(s.Templates) != 1 {
		t.Fatalf("templates: %d", len(s.Templates))
	}
	tmpl := s.Templates[0]
	if tmpl.TemplateID != 256 || tmpl.FieldCount != 5 {
		t.Errorf("template header: %+v", tmpl)
	}
	if tmpl.RecordSize != 13 {
		t.Errorf("record size: %d (expected 13)", tmpl.RecordSize)
	}
	want := []string{
		"sourceIPv4Address",
		"destinationIPv4Address",
		"sourceTransportPort",
		"destinationTransportPort",
		"protocolIdentifier",
	}
	for i, n := range want {
		if tmpl.Fields[i].TypeName != n {
			t.Errorf("field %d: got %q want %q",
				i, tmpl.Fields[i].TypeName, n)
		}
	}
}

func TestDecode_EnterpriseFieldSpecifier(t *testing.T) {
	// Template with 1 enterprise IE: type 1, Enterprise=9
	// (Cisco PEN).
	// Length = 16 (header) + 4 (set hdr) + 4 (template hdr)
	// + 8 (enterprise field spec) = 32 = 0x20.
	in := "000A 0020 60000000 00000001 00000001" +
		"0002 0010 0100 0001 8001 0004 00000009"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tmpl := r.Sets[0].Templates[0]
	if len(tmpl.Fields) != 1 {
		t.Fatalf("fields: %d", len(tmpl.Fields))
	}
	f := tmpl.Fields[0]
	if !f.IsEnterprise {
		t.Errorf("expected enterprise field")
	}
	if f.EnterpriseNumber != 9 {
		t.Errorf("enterprise number: %d", f.EnterpriseNumber)
	}
	if f.Type != 1 {
		t.Errorf("type (low 15 bits): %d", f.Type)
	}
}

func TestDecode_DataSet_RawHex(t *testing.T) {
	// Template + Data Set (one 13-byte record + 3 pad bytes).
	// Length = 16 + 28 + 20 = 64 = 0x40.
	in := "000A 0040 60000000 00000001 00000001" +
		"0002 001C 0100 0005 00080004 000C0004 00070002 000B0002 00040001" +
		"0100 0014 C0A80101 0A000001 0050 D431 06 000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Sets) != 2 {
		t.Fatalf("sets: %d", len(r.Sets))
	}
	data := r.Sets[1]
	if data.Kind != "Data Set" {
		t.Errorf("kind: %q", data.Kind)
	}
	if data.DataSet == nil {
		t.Fatal("data set body nil")
	}
	if data.DataSet.ReferencedTemplateID != 256 {
		t.Errorf("template ref: %d", data.DataSet.ReferencedTemplateID)
	}
	if data.DataSet.BodyBytes != 16 {
		t.Errorf("body bytes: %d", data.DataSet.BodyBytes)
	}
}

func TestDecode_OptionsTemplateSet(t *testing.T) {
	// Options Template: Template 256, FieldCount=2,
	// ScopeFieldCount=1, scope=observationPointId (138),
	// option=samplingInterval (34).
	// Body = 6 + 4 + 4 = 14. Set length = 4 + 14 = 18 = 0x12.
	// Header length = 16 + 18 = 34 = 0x22.
	in := "000A 0022 60000000 00000001 00000001" +
		"0003 0012 0100 0002 0001 008A0004 00220004"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	s := r.Sets[0]
	if s.Kind != "Options Template Set" {
		t.Errorf("kind: %q", s.Kind)
	}
	if len(s.OptionTemplates) != 1 {
		t.Fatalf("option templates: %d", len(s.OptionTemplates))
	}
	ot := s.OptionTemplates[0]
	if ot.TemplateID != 256 || ot.FieldCount != 2 || ot.ScopeFieldCount != 1 {
		t.Errorf("option template header: %+v", ot)
	}
	if len(ot.ScopeFields) != 1 || len(ot.OptionFields) != 1 {
		t.Errorf("scope/option split: %+v", ot)
	}
	if ot.ScopeFields[0].TypeName != "observationPointId" {
		t.Errorf("scope field: %q", ot.ScopeFields[0].TypeName)
	}
	if ot.OptionFields[0].TypeName != "samplingInterval" {
		t.Errorf("option field: %q", ot.OptionFields[0].TypeName)
	}
}

func TestDecode_FieldTypeNameSpotCheck(t *testing.T) {
	cases := map[int]string{
		1:   "octetDeltaCount",
		2:   "packetDeltaCount",
		4:   "protocolIdentifier",
		6:   "tcpControlBits",
		8:   "sourceIPv4Address",
		12:  "destinationIPv4Address",
		27:  "sourceIPv6Address",
		61:  "flowDirection",
		136: "flowEndReason",
		150: "flowStartSeconds",
		152: "flowStartMilliseconds",
	}
	for k, v := range cases {
		if got := fieldTypeName(k); got != v {
			t.Errorf("fieldTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedFieldType(t *testing.T) {
	if got := fieldTypeName(9999); !strings.Contains(got, "uncatalogued") {
		t.Errorf("uncatalogued IE: %q", got)
	}
}

func TestDecode_SetKindTable(t *testing.T) {
	cases := map[uint16]string{
		2:   "Template Set",
		3:   "Options Template Set",
		256: "Data Set",
		400: "Data Set",
	}
	for k, v := range cases {
		if got := setKind(k); got != v {
			t.Errorf("setKind(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UnsupportedVersion(t *testing.T) {
	// Version 9 (NetFlow v9; not handled here).
	in := "0009 0014 60000000 00000001 00000001 0000 0000"
	_, err := Decode(in)
	if err == nil {
		t.Fatal("expected error for v9")
	}
}

func TestDecode_LengthMismatch_Note(t *testing.T) {
	// Header declares Length=100 but only 16 bytes provided.
	in := "000A 0064 60000000 00000001 00000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "message length") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected length-mismatch note in: %v", r.Notes)
	}
}

func TestDecode_MultipleTemplatesInOneSet(t *testing.T) {
	// Two back-to-back templates in one Template Set.
	// Template 256: 2 fields (8 bytes). Template 257: 1 field
	// (4 bytes). Bodies total = 4 + 8 + 4 + 4 = 20.
	// Set length = 4 + 20 = 24 = 0x18.
	// Header length = 16 + 24 = 40 = 0x28.
	in := "000A 0028 60000000 00000001 00000001" +
		"0002 0018 0100 0002 00080004 000C0004" +
		"0101 0001 00040001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	tmpls := r.Sets[0].Templates
	if len(tmpls) != 2 {
		t.Fatalf("templates: %d", len(tmpls))
	}
	if tmpls[0].TemplateID != 256 || tmpls[1].TemplateID != 257 {
		t.Errorf("template IDs: %d / %d",
			tmpls[0].TemplateID, tmpls[1].TemplateID)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "000A 001",
		"short":   "000A 0010",
		"bad hex": "ZZ0A 0010 60000000 00000001 00000001",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
