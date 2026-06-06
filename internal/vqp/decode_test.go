// SPDX-License-Identifier: AGPL-3.0-or-later

package vqp

import (
	"strings"
	"testing"
)

// Vectors produced with scapy's VQP layer (scapy.contrib.vqp) and
// verified field-for-field.

func TestDecodeRequest(t *testing.T) {
	// VQP(type=1, errorcodeaction=0, unknown=6, seq=0x2748)
	//   /VQPEntry(3076,"engineering")/VQPEntry(3074,"FastEthernet0/1")
	//   /VQPEntry(3078,"00:11:22:33:44:55")/VQPEntry(3073,"10.0.0.1")
	const v = "010100060000274800000c04000b656e67696e656572696e6700000c02000f4661737445746865726e6574302f3100000c06000600112233445500000c0100040a000001"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Opcode != 1 || r.OpcodeName != "requestPort" {
		t.Fatalf("opcode = %d/%q", r.Opcode, r.OpcodeName)
	}
	if r.Sequence != 0x2748 {
		t.Errorf("seq = %#x, want 0x2748", r.Sequence)
	}
	if len(r.Entries) != 4 {
		t.Fatalf("entries = %d, want 4", len(r.Entries))
	}
	want := []struct {
		name string
		val  string
	}{
		{"Domain", "engineering"},
		{"portName", "FastEthernet0/1"},
		{"ReqMACAddress", "00:11:22:33:44:55"},
		{"clientIPAddress", "10.0.0.1"},
	}
	for i, w := range want {
		if r.Entries[i].DataTypeName != w.name || r.Entries[i].Value != w.val {
			t.Errorf("entry %d = %q/%q, want %q/%q", i, r.Entries[i].DataTypeName, r.Entries[i].Value, w.name, w.val)
		}
	}
}

func TestDecodeResponse(t *testing.T) {
	// VQP(type=2, unknown=2, seq=0x2748)/VQPEntry(3075,"accounting")
	//   /VQPEntry(3080,"00:11:22:33:44:55")
	const v = "010200020000274800000c03000a6163636f756e74696e6700000c080006001122334455"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OpcodeName != "responseVLAN" {
		t.Fatalf("opcode = %q", r.OpcodeName)
	}
	if len(r.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(r.Entries))
	}
	if r.Entries[0].DataTypeName != "VLANName" || r.Entries[0].Value != "accounting" {
		t.Errorf("VLAN entry = %q/%q", r.Entries[0].DataTypeName, r.Entries[0].Value)
	}
	if r.Entries[1].DataTypeName != "ResMACAddress" || r.Entries[1].Value != "00:11:22:33:44:55" {
		t.Errorf("MAC entry = %q/%q", r.Entries[1].DataTypeName, r.Entries[1].Value)
	}
}

func TestDecodeDenied(t *testing.T) {
	// VQP(type=2, errorcodeaction=3, seq=1)/VQPEntry(3075,"--NONE--")
	const v = "010203020000000100000c0300082d2d4e4f4e452d2d"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ResponseCode != 3 || r.ResponseName != "accessDenied" {
		t.Errorf("response = %d/%q, want 3/accessDenied", r.ResponseCode, r.ResponseName)
	}
	if r.Entries[0].Value != "--NONE--" {
		t.Errorf("VLAN = %q, want --NONE--", r.Entries[0].Value)
	}
	var denied bool
	for _, n := range r.Notes {
		if strings.Contains(n, "lockout") {
			denied = true
		}
	}
	if !denied {
		t.Error("expected a lockout note for accessDenied response")
	}
}

func TestDecodeRejectsNonVQP(t *testing.T) {
	if _, err := Decode("02010006" + "00000000"); err == nil {
		t.Fatal("expected rejection of version != 1")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("010100"); err == nil {
		t.Fatal("expected error on short header")
	}
}
