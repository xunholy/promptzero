package igmp

import (
	"strings"
	"testing"
)

func TestDecode_IGMPv2_GeneralQuery(t *testing.T) {
	// Type 0x11, Max Resp Time 100 (10s = 100 decisec), Checksum,
	// Group 0.0.0.0 (General Query).
	in := "11 64 ABCD 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	if r.TypeName != "Membership Query" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.GroupAddress != "0.0.0.0" {
		t.Errorf("group: %q", r.GroupAddress)
	}
	if r.MaxRespCs != 100 {
		t.Errorf("max resp cs: %d", r.MaxRespCs)
	}
}

func TestDecode_IGMPv2_MembershipReport(t *testing.T) {
	// Type 0x16, Group 224.1.2.3.
	in := "16 00 ABCD E0010203"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "IGMPv2 Membership Report" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.GroupAddress != "224.1.2.3" {
		t.Errorf("group: %q", r.GroupAddress)
	}
}

func TestDecode_IGMPv2_LeaveGroup(t *testing.T) {
	in := "17 00 ABCD E0010203"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "IGMPv2 Leave Group" {
		t.Errorf("type: %q", r.TypeName)
	}
}

func TestDecode_IGMPv3_GroupSpecificQuery(t *testing.T) {
	// v3 Query (12 bytes total): Type=0x11, Max Resp 100,
	// Checksum, Group 224.1.2.3, S=0 QRV=2 (byte 8=0x02),
	// QQIC=125 (default 0x7D), Sources=0.
	in := "11 64 ABCD E0010203 02 7D 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 3 {
		t.Errorf("version: %d", r.Version)
	}
	if r.SuppressRouterSide == nil || *r.SuppressRouterSide {
		t.Errorf("S flag: %+v", r.SuppressRouterSide)
	}
	if r.QRV == nil || *r.QRV != 2 {
		t.Errorf("QRV: %+v", r.QRV)
	}
	if r.QQICRaw == nil || *r.QQICRaw != 125 {
		t.Errorf("QQIC raw: %+v", r.QQICRaw)
	}
	if r.NumberOfSources == nil || *r.NumberOfSources != 0 {
		t.Errorf("num sources: %+v", r.NumberOfSources)
	}
}

func TestDecode_IGMPv3_GroupAndSourceSpecific(t *testing.T) {
	// v3 Query with 2 sources.
	in := "11 64 ABCD E0010203 02 7D 0002 C0A80101 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.NumberOfSources == nil || *r.NumberOfSources != 2 {
		t.Fatalf("num sources: %+v", r.NumberOfSources)
	}
	if len(r.SourceAddresses) != 2 {
		t.Fatalf("expected 2 source addresses, got %d",
			len(r.SourceAddresses))
	}
	if r.SourceAddresses[0] != "192.168.1.1" ||
		r.SourceAddresses[1] != "192.168.1.2" {
		t.Errorf("source addresses: %+v", r.SourceAddresses)
	}
}

func TestDecode_IGMPv3_MembershipReport_Include1Source(t *testing.T) {
	// Type 0x22, NumGroupRecords=1, record type 1
	// (MODE_IS_INCLUDE), 1 source, group 224.1.2.3,
	// source 192.168.1.1.
	in := "22 00 ABCD 0000 0001 01 00 0001 E0010203 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "IGMPv3 Membership Report" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.NumberOfGroupRecords == nil || *r.NumberOfGroupRecords != 1 {
		t.Fatalf("num records: %+v", r.NumberOfGroupRecords)
	}
	if len(r.GroupRecords) != 1 {
		t.Fatalf("group records: %d", len(r.GroupRecords))
	}
	rec := r.GroupRecords[0]
	if rec.RecordTypeName != "MODE_IS_INCLUDE" {
		t.Errorf("record type: %q", rec.RecordTypeName)
	}
	if rec.MulticastAddress != "224.1.2.3" {
		t.Errorf("multicast addr: %q", rec.MulticastAddress)
	}
	if len(rec.SourceAddresses) != 1 || rec.SourceAddresses[0] != "192.168.1.1" {
		t.Errorf("source: %+v", rec.SourceAddresses)
	}
}

func TestDecode_IGMPv3_ReportMultipleRecords(t *testing.T) {
	// 2 records: INCLUDE empty + EXCLUDE with 2 sources.
	in := "22 00 ABCD 0000 0002" +
		"01 00 0000 E0010203" +
		"02 00 0002 E0010204 C0A80101 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.GroupRecords) != 2 {
		t.Fatalf("expected 2 records, got %d", len(r.GroupRecords))
	}
	if r.GroupRecords[0].RecordTypeName != "MODE_IS_INCLUDE" ||
		r.GroupRecords[1].RecordTypeName != "MODE_IS_EXCLUDE" {
		t.Errorf("record types: %+v", r.GroupRecords)
	}
	if len(r.GroupRecords[1].SourceAddresses) != 2 {
		t.Errorf("record 1 sources: %d",
			len(r.GroupRecords[1].SourceAddresses))
	}
}

func TestDecode_MaxRespCode_ExpMantissa(t *testing.T) {
	cases := map[int]int{
		0:    0,
		100:  100,
		127:  127,
		0x80: 128,   // exp=0, mant=0 → 0x10 << 3 = 128
		0x95: 336,   // exp=1, mant=5 → 0x15 << 4 = 336
		0xFF: 31744, // exp=7, mant=F → 0x1F << 10 = 31744
	}
	for raw, want := range cases {
		got := decodeMaxRespCode(raw)
		if got != want {
			t.Errorf("decodeMaxRespCode(0x%02X): got %d want %d", raw, got, want)
		}
	}
}

func TestDecode_TypeNameTable(t *testing.T) {
	cases := map[int]string{
		0x11: "Membership Query",
		0x12: "IGMPv1 Membership Report",
		0x16: "IGMPv2 Membership Report",
		0x17: "IGMPv2 Leave Group",
		0x22: "IGMPv3 Membership Report",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(0x%02X): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_RecordTypeTable(t *testing.T) {
	cases := map[int]string{
		1: "MODE_IS_INCLUDE",
		2: "MODE_IS_EXCLUDE",
		3: "CHANGE_TO_INCLUDE_MODE",
		4: "CHANGE_TO_EXCLUDE_MODE",
		5: "ALLOW_NEW_SOURCES",
		6: "BLOCK_OLD_SOURCES",
	}
	for k, v := range cases {
		if got := recordTypeName(k); got != v {
			t.Errorf("recordTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedType_Note(t *testing.T) {
	in := "99 00 ABCD 00000000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !strings.Contains(r.TypeName, "uncatalogued") {
		t.Errorf("expected uncatalogued type name, got %q", r.TypeName)
	}
	if len(r.Notes) == 0 {
		t.Errorf("expected note for uncatalogued type")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "1164",
		"short":   "1164ABCD",
		"bad hex": "ZZ64 ABCD 00000000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
