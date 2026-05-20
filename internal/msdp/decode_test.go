package msdp

import (
	"strings"
	"testing"
)

func TestDecode_Keepalive(t *testing.T) {
	in := "04 0003"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Messages) != 1 {
		t.Fatalf("messages: %d", len(r.Messages))
	}
	m := r.Messages[0]
	if m.TypeName != "Keepalive" {
		t.Errorf("type: %q", m.TypeName)
	}
	if m.Length != 3 {
		t.Errorf("length: %d", m.Length)
	}
}

func TestDecode_SourceActive_OneEntry(t *testing.T) {
	// SA with RP=192.168.1.1, 1 entry: group=239.1.2.3,
	// source=10.0.0.1, prefix=32.
	in := "01 0014 01 C0A80101 000000 20 EF010203 0A000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	sa := r.Messages[0].SourceActive
	if sa == nil {
		t.Fatal("SA body nil")
	}
	if sa.EntryCount != 1 {
		t.Errorf("entry count: %d", sa.EntryCount)
	}
	if sa.RPAddress != "192.168.1.1" {
		t.Errorf("RP: %q", sa.RPAddress)
	}
	if len(sa.Entries) != 1 {
		t.Fatalf("entries: %d", len(sa.Entries))
	}
	e := sa.Entries[0]
	if e.SprefixLength != 32 ||
		e.GroupAddress != "239.1.2.3" ||
		e.SourceAddress != "10.0.0.1" {
		t.Errorf("entry: %+v", e)
	}
}

func TestDecode_SourceActive_MultipleEntries(t *testing.T) {
	// SA with RP=192.168.1.1, 2 entries.
	in := "01 0020 02 C0A80101" +
		"000000 20 EF010203 0A000001" +
		"000000 20 EF010204 0A000002"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	sa := r.Messages[0].SourceActive
	if len(sa.Entries) != 2 {
		t.Fatalf("entries: %d", len(sa.Entries))
	}
	if sa.Entries[0].GroupAddress != "239.1.2.3" ||
		sa.Entries[1].GroupAddress != "239.1.2.4" {
		t.Errorf("entry groups: %s / %s",
			sa.Entries[0].GroupAddress, sa.Entries[1].GroupAddress)
	}
}

func TestDecode_SourceActive_WithEncapsulated(t *testing.T) {
	// SA with 1 entry + 4 bytes of encapsulated data
	// after the entries.
	in := "01 0018 01 C0A80101" +
		"000000 20 EF010203 0A000001" +
		"DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	sa := r.Messages[0].SourceActive
	if sa.EncapsulatedBytes != 4 {
		t.Errorf("encapsulated bytes: %d", sa.EncapsulatedBytes)
	}
	if sa.EncapsulatedHex != "DEADBEEF" {
		t.Errorf("encapsulated hex: %q", sa.EncapsulatedHex)
	}
}

func TestDecode_SARequest(t *testing.T) {
	in := "02 0008 00 EF010203"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	req := r.Messages[0].SARequest
	if req == nil {
		t.Fatal("SA Request nil")
	}
	if req.GroupAddress != "239.1.2.3" {
		t.Errorf("group: %q", req.GroupAddress)
	}
}

func TestDecode_SAResponse(t *testing.T) {
	// SA Response has same layout as SA (just type=3).
	in := "03 0014 01 C0A80101 000000 20 EF010203 0A000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Messages[0].TypeName != "IPv4 SA Response" {
		t.Errorf("type: %q", r.Messages[0].TypeName)
	}
	if r.Messages[0].SAResponse == nil {
		t.Fatal("SA Response body nil")
	}
	if r.Messages[0].SAResponse.RPAddress != "192.168.1.1" {
		t.Errorf("RP: %q", r.Messages[0].SAResponse.RPAddress)
	}
}

func TestDecode_NotificationHoldTimerExpired(t *testing.T) {
	// Notification: O=0, Error=4 (Hold Timer Expired), sub=0.
	in := "06 0005 04 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	n := r.Messages[0].Notification
	if n == nil {
		t.Fatal("Notification body nil")
	}
	if n.ErrorCode != 4 || n.ErrorCodeName != "Hold Timer Expired" {
		t.Errorf("error: %d %q", n.ErrorCode, n.ErrorCodeName)
	}
	if n.OpenBit {
		t.Errorf("O bit should be clear")
	}
}

func TestDecode_NotificationOpenBit(t *testing.T) {
	// Notification with O=1, Error=2 (SA-Request Error).
	in := "06 0005 82 01"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	n := r.Messages[0].Notification
	if !n.OpenBit || n.ErrorCode != 2 {
		t.Errorf("notification: %+v", n)
	}
}

func TestDecode_MultipleTLVs(t *testing.T) {
	// Keepalive followed by SA.
	in := "04 0003" +
		"01 0014 01 C0A80101 000000 20 EF010203 0A000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Messages) != 2 {
		t.Fatalf("messages: %d", len(r.Messages))
	}
	if r.Messages[0].TypeName != "Keepalive" ||
		r.Messages[1].TypeName != "IPv4 Source-Active" {
		t.Errorf("types: %s / %s",
			r.Messages[0].TypeName, r.Messages[1].TypeName)
	}
}

func TestDecode_TypeNameTable(t *testing.T) {
	cases := map[int]string{
		1: "IPv4 Source-Active",
		2: "IPv4 SA Request",
		3: "IPv4 SA Response",
		4: "Keepalive",
		6: "Notification",
		7: "Traceroute in Progress (deprecated)",
		8: "Traceroute Reply (deprecated)",
	}
	for k, v := range cases {
		if got := typeName(k); got != v {
			t.Errorf("typeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_ErrorCodeTable(t *testing.T) {
	cases := map[int]string{
		0: "Reserved",
		1: "Message Header Error",
		2: "SA-Request Error",
		3: "SA-Message/SA-Response Error",
		4: "Hold Timer Expired",
		5: "Finite State Machine Error",
		6: "Notification",
		7: "Cease",
	}
	for k, v := range cases {
		if got := errorCodeName(k); got != v {
			t.Errorf("errorCodeName(%d): got %q want %q", k, got, v)
		}
	}
}

func TestDecode_UncataloguedType_Note(t *testing.T) {
	// Type 99 (not 1-4, 6, or deprecated 7-8).
	in := "63 0003"
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

func TestDecode_TruncatedTLV_Note(t *testing.T) {
	// SA declares length 20 but only 8 bytes available
	// after the TLV header.
	in := "01 0014 01 C0A80101 0000"
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
		"odd hex": "04 000",
		"short":   "04 00",
		"bad hex": "ZZ 0003",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
