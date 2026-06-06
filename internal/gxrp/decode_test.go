// SPDX-License-Identifier: AGPL-3.0-or-later

package gxrp

import (
	"strings"
	"testing"
)

// Vectors produced with scapy's GARP layer (scapy.contrib.gxrp) and
// verified field-for-field.

func TestDecodeGVRP(t *testing.T) {
	// GARP(msgs=[GARP_MESSAGE(type=1, attrs=[JoinIn/GVRP(100),
	//   JoinIn/GVRP(200), LeaveAll])])
	const v = "00010104020064040200c802000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProtocolID != 1 {
		t.Fatalf("proto = %d", r.ProtocolID)
	}
	if len(r.Messages) != 1 || r.Messages[0].Type != 1 {
		t.Fatalf("messages = %+v", r.Messages)
	}
	attrs := r.Messages[0].Attributes
	if len(attrs) != 3 {
		t.Fatalf("attrs = %d, want 3", len(attrs))
	}
	if attrs[0].EventName != "JoinIn" || attrs[0].Kind != "vlan" || attrs[0].VLAN == nil || *attrs[0].VLAN != 100 {
		t.Errorf("attr0 = %+v", attrs[0])
	}
	if attrs[1].VLAN == nil || *attrs[1].VLAN != 200 {
		t.Errorf("attr1 vlan = %v", attrs[1].VLAN)
	}
	if attrs[2].EventName != "LeaveAll" || attrs[2].Kind != "" || attrs[2].Length != 2 {
		t.Errorf("attr2 (LeaveAll) = %+v", attrs[2])
	}
}

func TestDecodeGMRPGroup(t *testing.T) {
	// GARP(msgs=[GARP_MESSAGE(type=1, attrs=[JoinIn/GMRP_GROUP(01:00:5e:01:02:03)])])
	const v = "000101080201005e0102030000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	a := r.Messages[0].Attributes[0]
	if a.Kind != "group_mac" || a.GroupMAC != "01:00:5e:01:02:03" {
		t.Errorf("group attr = %+v", a)
	}
}

func TestDecodeGMRPService(t *testing.T) {
	// GARP(msgs=[GARP_MESSAGE(type=2, attrs=[JoinIn/GMRP_SERVICE(0)])])
	const v = "0001020302000000"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Messages[0].Type != 2 {
		t.Errorf("type = %d, want 2", r.Messages[0].Type)
	}
	a := r.Messages[0].Attributes[0]
	if a.Kind != "gmrp_service" || a.Service != "All Groups" {
		t.Errorf("service attr = %+v", a)
	}
}

func TestDecodeRejectsNonGARP(t *testing.T) {
	if _, err := Decode("000201"); err == nil {
		t.Fatal("expected rejection of proto id != 1")
	}
}

func TestDecodeTruncated(t *testing.T) {
	if _, err := Decode("0001"); err == nil {
		t.Fatal("expected error on short input")
	}
}

func TestDecodeBadAttributeLength(t *testing.T) {
	// proto 0001, msg type 01, attribute len 0x01 (invalid, < 2)
	const v = "0001010100"
	r, err := Decode(v)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var noted bool
	for _, n := range r.Notes {
		if strings.Contains(n, "invalid or overruns") {
			noted = true
		}
	}
	if !noted {
		t.Error("expected an invalid-length note")
	}
}
