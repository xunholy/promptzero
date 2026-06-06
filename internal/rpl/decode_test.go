// SPDX-License-Identifier: AGPL-3.0-or-later

package rpl

import "testing"

// All vectors were produced with scapy's RPL layer (scapy.contrib.rpl +
// scapy.layers.inet6.ICMPv6RPL) and verified field-for-field.

func TestDecodeDIO(t *testing.T) {
	// ICMPv6RPL(code=1)/RPLDIO(RPLInstanceID=30, ver=240, rank=256, G=1,
	//   mop=2, prf=4, dtsn=1, dodagid="2001:db8::1")
	const v = "9b0100001ef001009401000020010db8000000000000000000000001"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ICMPv6Type != 155 || r.Code != 1 {
		t.Fatalf("type/code = %d/%d, want 155/1", r.ICMPv6Type, r.Code)
	}
	if r.RPLInstanceID == nil || *r.RPLInstanceID != 30 {
		t.Errorf("instance id = %v, want 30", r.RPLInstanceID)
	}
	if r.Version == nil || *r.Version != 240 {
		t.Errorf("version = %v, want 240", r.Version)
	}
	if r.Rank == nil || *r.Rank != 256 {
		t.Errorf("rank = %v, want 256", r.Rank)
	}
	if r.Grounded == nil || !*r.Grounded {
		t.Errorf("grounded = %v, want true", r.Grounded)
	}
	if r.MOP == nil || *r.MOP != 2 {
		t.Errorf("mop = %v, want 2", r.MOP)
	}
	if r.MOPName != "Storing without multicast" {
		t.Errorf("mop name = %q", r.MOPName)
	}
	if r.Preference == nil || *r.Preference != 4 {
		t.Errorf("prf = %v, want 4", r.Preference)
	}
	if r.DTSN == nil || *r.DTSN != 1 {
		t.Errorf("dtsn = %v, want 1", r.DTSN)
	}
	if r.DODAGID != "2001:db8::1" {
		t.Errorf("dodagid = %q, want 2001:db8::1", r.DODAGID)
	}
}

func TestDecodeDIS(t *testing.T) {
	// ICMPv6RPL(code=0)/RPLDIS()
	const v = "9b0000000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Code != 0 || r.MessageName != "DIS (DODAG Information Solicitation)" {
		t.Fatalf("code/name = %d/%q", r.Code, r.MessageName)
	}
	if r.RPLInstanceID != nil {
		t.Errorf("DIS should carry no instance id, got %v", *r.RPLInstanceID)
	}
}

func TestDecodeDAO(t *testing.T) {
	// ICMPv6RPL(code=2)/RPLDAO(RPLInstanceID=30, K=1, D=1, daoseq=5,
	//   dodagid="2001:db8::2")
	const v = "9b0200001ec0000520010db8000000000000000000000002"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Code != 2 {
		t.Fatalf("code = %d, want 2", r.Code)
	}
	if r.RPLInstanceID == nil || *r.RPLInstanceID != 30 {
		t.Errorf("instance id = %v, want 30", r.RPLInstanceID)
	}
	if r.DAOSequence == nil || *r.DAOSequence != 5 {
		t.Errorf("dao seq = %v, want 5", r.DAOSequence)
	}
	if r.DODAGID != "2001:db8::2" {
		t.Errorf("dodagid = %q, want 2001:db8::2", r.DODAGID)
	}
}

func TestDecodeSeparators(t *testing.T) {
	const v = "9b:01:00:00:1e:f0:01:00:94:01:00:00:20:01:0d:b8:00:00:00:00:00:00:00:00:00:00:00:01"
	r, err := Decode("0x" + v)
	if err != nil {
		t.Fatalf("Decode with separators: %v", err)
	}
	if r.Rank == nil || *r.Rank != 256 {
		t.Errorf("rank = %v, want 256", r.Rank)
	}
}

func TestDecodeRejectsNonRPL(t *testing.T) {
	if _, err := Decode("85000000"); err == nil { // ICMPv6 type 133 (RS)
		t.Fatal("expected rejection of non-RPL ICMPv6 type")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("9b01"); err == nil {
		t.Fatal("expected error on short input")
	}
	if _, err := Decode("9b0100001ef0"); err == nil {
		t.Fatal("expected error on truncated DIO body")
	}
}
