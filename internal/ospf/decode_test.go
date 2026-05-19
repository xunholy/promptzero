package ospf

import (
	"strings"
	"testing"
)

func TestDecode_Hello(t *testing.T) {
	// Common header 24 bytes + Hello body 24 bytes = 48 total = 0x0030.
	// Hello body: mask 255.255.255.0, interval 10s, E flag, pri 1,
	// dead 40s, DR 192.168.1.1, BDR 192.168.1.2, 1 neighbor 192.168.1.2.
	in := "02 01 0030 C0A80101 00000000 0000 0000 0000000000000000" +
		"FFFFFF00 000A 02 01 00000028 C0A80101 C0A80102 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 || r.TypeName != "Hello" {
		t.Errorf("version/type: %d / %q", r.Version, r.TypeName)
	}
	if r.RouterID != "192.168.1.1" {
		t.Errorf("router id: %q", r.RouterID)
	}
	if r.AreaID != "0.0.0.0" {
		t.Errorf("area id: %q", r.AreaID)
	}
	if r.AuTypeName != "Null (no authentication)" {
		t.Errorf("au type: %q", r.AuTypeName)
	}
	if r.Hello == nil {
		t.Fatal("Hello nil")
	}
	if r.Hello.NetworkMask != "255.255.255.0" {
		t.Errorf("mask: %q", r.Hello.NetworkMask)
	}
	if r.Hello.HelloInterval != 10 {
		t.Errorf("hello interval: %d", r.Hello.HelloInterval)
	}
	if r.Hello.RtrPri != 1 {
		t.Errorf("router pri: %d", r.Hello.RtrPri)
	}
	if r.Hello.RouterDeadInterval != 40 {
		t.Errorf("dead interval: %d", r.Hello.RouterDeadInterval)
	}
	if r.Hello.DesignatedRouter != "192.168.1.1" {
		t.Errorf("DR: %q", r.Hello.DesignatedRouter)
	}
	if r.Hello.BackupDesignatedRouter != "192.168.1.2" {
		t.Errorf("BDR: %q", r.Hello.BackupDesignatedRouter)
	}
	if len(r.Hello.Neighbors) != 1 || r.Hello.Neighbors[0] != "192.168.1.2" {
		t.Errorf("neighbors: %+v", r.Hello.Neighbors)
	}
	found := false
	for _, o := range r.Hello.OptionsDecoded {
		if strings.Contains(o, "E (External)") {
			found = true
		}
	}
	if !found {
		t.Errorf("E option should be decoded: %v", r.Hello.OptionsDecoded)
	}
}

func TestDecode_DBD(t *testing.T) {
	in := "02 02 0034 C0A80101 00000000 0000 0000 0000000000000000" +
		"05DC 02 07 12345678" +
		"0E10 02 01 C0A80101 C0A80101 80000001 ABCD 0030"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Database Description (DBD)" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.DBD == nil {
		t.Fatal("DBD nil")
	}
	if r.DBD.InterfaceMTU != 1500 {
		t.Errorf("MTU: %d", r.DBD.InterfaceMTU)
	}
	if !r.DBD.IBit || !r.DBD.MBit || !r.DBD.MSBit {
		t.Errorf("I/M/MS flags: %v %v %v", r.DBD.IBit, r.DBD.MBit, r.DBD.MSBit)
	}
	if r.DBD.DDSequenceNumber != 0x12345678 {
		t.Errorf("seq: 0x%X", r.DBD.DDSequenceNumber)
	}
	if len(r.DBD.LSAHeaders) != 1 {
		t.Fatalf("expected 1 LSA header, got %d", len(r.DBD.LSAHeaders))
	}
	lh := r.DBD.LSAHeaders[0]
	if lh.LSTypeName != "Router LSA" {
		t.Errorf("LS type: %q", lh.LSTypeName)
	}
	if lh.LinkStateID != "192.168.1.1" {
		t.Errorf("Link State ID: %q", lh.LinkStateID)
	}
}

func TestDecode_LSR(t *testing.T) {
	// LSR with 1 request: LS Type 1, ID 192.168.1.0, Adv 192.168.1.1.
	in := "02 03 0024 C0A80101 00000000 0000 0000 0000000000000000" +
		"00000001 C0A80100 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Link State Request (LSR)" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.LSR == nil || len(r.LSR.Requests) != 1 {
		t.Fatalf("LSR: %+v", r.LSR)
	}
	req := r.LSR.Requests[0]
	if req.LSTypeName != "Router LSA" {
		t.Errorf("LS type: %q", req.LSTypeName)
	}
	if req.LinkStateID != "192.168.1.0" {
		t.Errorf("Link State ID: %q", req.LinkStateID)
	}
	if req.AdvertisingRouter != "192.168.1.1" {
		t.Errorf("Advertising Router: %q", req.AdvertisingRouter)
	}
}

func TestDecode_LSU(t *testing.T) {
	// LSU with 1 LSA: header only (Length=20).
	in := "02 04 0030 C0A80101 00000000 0000 0000 0000000000000000" +
		"00000001" +
		"0E10 02 01 C0A80101 C0A80101 80000001 ABCD 0014"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Link State Update (LSU)" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.LSU == nil {
		t.Fatal("LSU nil")
	}
	if r.LSU.NumberOfLSAs != 1 {
		t.Errorf("LSA count: %d", r.LSU.NumberOfLSAs)
	}
	if len(r.LSU.LSAs) != 1 {
		t.Fatalf("LSA list length: %d", len(r.LSU.LSAs))
	}
	if r.LSU.LSAs[0].LSTypeName != "Router LSA" {
		t.Errorf("LSA type: %q", r.LSU.LSAs[0].LSTypeName)
	}
}

func TestDecode_LSAck(t *testing.T) {
	// LSAck with 1 LSA header.
	in := "02 05 002C C0A80101 00000000 0000 0000 0000000000000000" +
		"0E10 02 01 C0A80101 C0A80101 80000001 ABCD 0030"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TypeName != "Link State Acknowledgment (LSAck)" {
		t.Errorf("type: %q", r.TypeName)
	}
	if r.LSAck == nil || len(r.LSAck.LSAHeaders) != 1 {
		t.Fatalf("LSAck: %+v", r.LSAck)
	}
}

func TestDecode_HelloWithMultipleNeighbors(t *testing.T) {
	// Hello with 3 neighbors. Body = 20 + 3*4 = 32 bytes. Total = 56 = 0x0038.
	in := "02 01 0038 C0A80101 00000000 0000 0000 0000000000000000" +
		"FFFFFF00 000A 02 01 00000028 C0A80101 C0A80102" +
		"C0A80102 C0A80103 C0A80104"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Hello.Neighbors) != 3 {
		t.Fatalf("expected 3 neighbors, got %d", len(r.Hello.Neighbors))
	}
}

func TestDecode_AuTypeTable(t *testing.T) {
	cases := map[int]string{
		0: "Null (no authentication)",
		1: "Simple Password",
		2: "Cryptographic Authentication (MD5)",
	}
	for k, v := range cases {
		if got := auTypeName(k); got != v {
			t.Errorf("auTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_LSTypeTable(t *testing.T) {
	cases := map[int]string{
		1:  "Router LSA",
		2:  "Network LSA",
		3:  "Summary LSA (network)",
		4:  "Summary LSA (ASBR)",
		5:  "AS-External LSA",
		7:  "NSSA External LSA (RFC 3101)",
		9:  "Link-Local Opaque LSA (RFC 5250)",
		10: "Area-Local Opaque LSA",
		11: "AS-wide Opaque LSA",
	}
	for k, v := range cases {
		if got := lsTypeName(k); got != v {
			t.Errorf("lsTypeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_VersionMismatchNote(t *testing.T) {
	in := "03 01 0030 C0A80101 00000000 0000 0000 0000000000000000" +
		"FFFFFF00 000A 02 01 00000028 C0A80101 C0A80102 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "version is 3") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "020100",
		"short":   "02010030",
		"bad hex": "ZZ010030 C0A80101 00000000 0000 0000 0000000000000000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
