package ospfv3

import (
	"strings"
	"testing"
)

func TestDecode_Hello_OneNeighbor(t *testing.T) {
	// V=3, Type=1 Hello, Length=40, Router ID 1.1.1.1,
	// Area 0.0.0.0, Instance ID 0. Body: InterfaceID=1,
	// Priority=1, Options=0x000013 (V6+E+R), Hello=10s,
	// Dead=40s, DR=1.1.1.1, BDR=0.0.0.0, Neighbor 2.2.2.2.
	in := "03 01 0028 01010101 00000000 ABCD 00 00" +
		"00000001 01 000013 000A 0028 01010101 00000000 02020202"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 3 || r.TypeName != "Hello" {
		t.Errorf("ver/type: %d %q", r.Version, r.TypeName)
	}
	if r.RouterID != "1.1.1.1" || r.AreaID != "0.0.0.0" {
		t.Errorf("ids: router=%q area=%q", r.RouterID, r.AreaID)
	}
	if r.Hello == nil {
		t.Fatal("Hello body nil")
	}
	h := r.Hello
	if h.InterfaceID != 1 || h.RouterPriority != 1 {
		t.Errorf("iface/pri: %+v", h)
	}
	if h.HelloIntervalSec != 10 || h.RouterDeadIntervalSec != 40 {
		t.Errorf("timers: hello=%d dead=%d",
			h.HelloIntervalSec, h.RouterDeadIntervalSec)
	}
	if !h.OptionFlags.V6 || !h.OptionFlags.E || !h.OptionFlags.R {
		t.Errorf("option flags: %+v", h.OptionFlags)
	}
	if h.OptionFlags.MC || h.OptionFlags.N || h.OptionFlags.DC {
		t.Errorf("unexpected option flags: %+v", h.OptionFlags)
	}
	if h.DesignatedRouterID != "1.1.1.1" || h.BackupDR_ID != "0.0.0.0" {
		t.Errorf("DR/BDR: %s / %s", h.DesignatedRouterID, h.BackupDR_ID)
	}
	if len(h.Neighbors) != 1 || h.Neighbors[0] != "2.2.2.2" {
		t.Errorf("neighbors: %+v", h.Neighbors)
	}
}

func TestDecode_DBD_NoLSAs(t *testing.T) {
	// V=3, Type=2 DBD, Length=28, Router ID 1.1.1.1.
	// Body: Reserved + Options=0x000013 + MTU=1500 +
	// Reserved + Flags=0x07 (I+M+MS) + DDSeq=1.
	in := "03 02 001C 01010101 00000000 ABCD 00 00" +
		"00 000013 05DC 00 07 00000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Database Description" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.DBD == nil {
		t.Fatal("DBD body nil")
	}
	d := r.DBD
	if d.InterfaceMTU != 1500 {
		t.Errorf("MTU: %d", d.InterfaceMTU)
	}
	if !d.FlagInit || !d.FlagMore || !d.FlagMasterSlave {
		t.Errorf("flags: %+v", d)
	}
	if d.DDSequenceNumber != 1 {
		t.Errorf("DD seq: %d", d.DDSequenceNumber)
	}
}

func TestDecode_LSR_OneRecord(t *testing.T) {
	// V=3, Type=3 LSR, Length=28. 1 record: LS Type
	// 0x00002001 Router-LSA, Link State ID 0.0.0.0,
	// Advertising Router 1.1.1.1.
	in := "03 03 001C 01010101 00000000 ABCD 00 00" +
		"00002001 00000000 01010101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Link State Request" {
		t.Errorf("type: %q", r.TypeName)
	}
	if len(r.LSR) != 1 {
		t.Fatalf("LSR records: %d", len(r.LSR))
	}
	rec := r.LSR[0]
	if rec.LSType != 0x00002001 || rec.LSTypeName != "Router-LSA" {
		t.Errorf("LS type: 0x%08X %q", rec.LSType, rec.LSTypeName)
	}
	if rec.LinkStateID != "0.0.0.0" || rec.AdvertisingRouter != "1.1.1.1" {
		t.Errorf("ids: lsid=%q adv=%q", rec.LinkStateID, rec.AdvertisingRouter)
	}
}

func TestDecode_LSU_OneLSAHeaderOnly(t *testing.T) {
	// LSU with 1 LSA whose Length = 20 (header only, no body).
	in := "03 04 0028 01010101 00000000 ABCD 00 00" +
		"00000001" +
		"0001 2001 00000000 01010101 80000001 CDEF 0014"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.LSU == nil {
		t.Fatal("LSU body nil")
	}
	if r.LSU.NumberOfLSAs != 1 {
		t.Errorf("num LSAs: %d", r.LSU.NumberOfLSAs)
	}
	if len(r.LSU.LSAHeaders) != 1 {
		t.Fatalf("LSA headers: %d", len(r.LSU.LSAHeaders))
	}
	h := r.LSU.LSAHeaders[0]
	if h.LSTypeName != "Router-LSA" {
		t.Errorf("LS type name: %q", h.LSTypeName)
	}
	if h.AdvertisingRouter != "1.1.1.1" {
		t.Errorf("adv router: %q", h.AdvertisingRouter)
	}
	if h.LSSequenceNumber != -2147483647 {
		// 0x80000001 as int32 = -2147483647
		t.Errorf("LS seq: %d", h.LSSequenceNumber)
	}
}

func TestDecode_LSAck_TwoHeaders(t *testing.T) {
	in := "03 05 0038 01010101 00000000 ABCD 00 00" +
		"0001 2001 00000000 01010101 80000001 CDEF 0014" +
		"0001 2009 00000001 02020202 80000002 CDEF 0024"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Link State Acknowledgment" {
		t.Errorf("type: %q", r.TypeName)
	}
	if len(r.LSAck) != 2 {
		t.Fatalf("LSAck headers: %d", len(r.LSAck))
	}
	if r.LSAck[0].LSTypeName != "Router-LSA" ||
		r.LSAck[1].LSTypeName != "Intra-Area-Prefix-LSA" {
		t.Errorf("LS types: %q / %q",
			r.LSAck[0].LSTypeName, r.LSAck[1].LSTypeName)
	}
	if r.LSAck[0].FloodingScopeName != "Area" {
		t.Errorf("scope: %q", r.LSAck[0].FloodingScopeName)
	}
}

func TestDecode_OptionFlagBits(t *testing.T) {
	// All 6 named bits set: V6+E+MC+N+R+DC = 0x3F.
	o := decodeOptions(0x3F)
	if !o.V6 || !o.E || !o.MC || !o.N || !o.R || !o.DC {
		t.Errorf("expected all options set: %+v", o)
	}
	z := decodeOptions(0)
	if z.V6 || z.E || z.MC || z.N || z.R || z.DC {
		t.Errorf("expected no options set: %+v", z)
	}
}

func TestDecode_TypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "Hello",
		2: "Database Description",
		3: "Link State Request",
		4: "Link State Update",
		5: "Link State Acknowledgment",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_LSTypeNameTable(t *testing.T) {
	// Function-code lookups (table uses lt & 0x1FFF).
	cases := map[int]string{
		0x2001: "Router-LSA",
		0x2002: "Network-LSA",
		0x2003: "Inter-Area-Prefix-LSA",
		0x2004: "Inter-Area-Router-LSA",
		0x4005: "AS-External-LSA",
		0x2006: "Group-Membership-LSA",
		0x2007: "Type-7-LSA (NSSA External)",
		0x0008: "Link-LSA",
		0x2009: "Intra-Area-Prefix-LSA",
	}
	for k, v := range cases {
		if got := lsTypeName(k); got != v {
			t.Errorf("lsTypeName(0x%04X): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_FloodingScopeTable(t *testing.T) {
	cases := map[int]string{
		0: "Link-Local",
		1: "Area",
		2: "AS",
	}
	for k, v := range cases {
		if got := floodingScopeName(k); got != v {
			t.Errorf("floodingScopeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionNot3_Note(t *testing.T) {
	// V=2 (OSPFv2 — not handled).
	in := "02 01 0028 01010101 00000000 ABCD 00 00" +
		"00000001 01 000013 000A 0028 01010101 00000000 02020202"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "OSPFv3") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected OSPFv3 note in: %v", r.Notes)
	}
}

func TestDecode_UncataloguedType_Note(t *testing.T) {
	// Type 99 (not 1-5).
	in := "03 63 0010 01010101 00000000 ABCD 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "uncatalogued") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected uncatalogued note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "03 01 002",
		"short":   "03 01 0010 01010101",
		"bad hex": "ZZ 01 0028 01010101 00000000 ABCD 0000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
