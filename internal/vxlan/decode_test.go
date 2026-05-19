package vxlan

import (
	"strings"
	"testing"
)

func TestDecode_StandardVXLAN_InnerIPv4(t *testing.T) {
	// Flags=0x08 (I=1), VNI=0xABCDEF (bytes 4-6), reserved-2=0,
	// inner Ethernet with dst MAC AA:BB:CC:DD:EE:FF, src MAC
	// 11:22:33:44:55:66, EtherType IPv4, 4 bytes inner payload.
	// 8-byte header: 08 00 00 00 AB CD EF 00.
	in := "08000000 ABCDEF 00 AABBCCDDEEFF 112233445566 0800 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.IFlag {
		t.Errorf("expected I-flag set")
	}
	if r.VNI != 0xABCDEF {
		t.Errorf("VNI: 0x%06X", r.VNI)
	}
	if r.Variant != "standard VXLAN (RFC 7348)" {
		t.Errorf("variant: %q", r.Variant)
	}
	if r.InnerEthernet == nil {
		t.Fatal("InnerEthernet nil")
	}
	if r.InnerEthernet.DstMAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("dst MAC: %q", r.InnerEthernet.DstMAC)
	}
	if r.InnerEthernet.SrcMAC != "11:22:33:44:55:66" {
		t.Errorf("src MAC: %q", r.InnerEthernet.SrcMAC)
	}
	if r.InnerEthernet.EtherTypeName != "IPv4" {
		t.Errorf("ether type: %q", r.InnerEthernet.EtherTypeName)
	}
	if r.InnerEthernet.RemainingBytes != 4 {
		t.Errorf("remaining: %d", r.InnerEthernet.RemainingBytes)
	}
	if len(r.Notes) != 0 {
		t.Errorf("expected no notes, got %v", r.Notes)
	}
}

func TestDecode_VXLAN_GBP_Cisco(t *testing.T) {
	// Flags=0x88 (I=1, G=1 group policy applied),
	// Reserved-1 middle 16 bits = GroupPolicyID 0x1234,
	// VNI=100. 8-byte header: 88 00 12 34 00 00 64 00.
	in := "88001234 000064 00 AABBCCDDEEFF 112233445566 0806 ABCD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Variant != "VXLAN-GBP (Cisco Group-Based Policy)" {
		t.Errorf("variant: %q", r.Variant)
	}
	if r.GBP == nil {
		t.Fatal("GBP nil")
	}
	if !r.GBP.GroupPolicyApplied {
		t.Errorf("group policy applied should be true")
	}
	if r.GBP.GroupPolicyID != 0x1234 {
		t.Errorf("group policy ID: 0x%04X", r.GBP.GroupPolicyID)
	}
	if r.VNI != 100 {
		t.Errorf("VNI: %d", r.VNI)
	}
}

func TestDecode_VXLAN_GPE_IPv4(t *testing.T) {
	// Flags=0x08 (I=1), VNI=1, Reserved-2=0x01 (NextProto IPv4).
	// 8-byte header: 08 00 00 00 00 00 01 01.
	in := "08000000 000001 01 45000028000000004006B1E6 7F0000017F000001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Variant != "VXLAN-GPE (Generic Protocol Extension)" {
		t.Errorf("variant: %q", r.Variant)
	}
	if r.GPE == nil {
		t.Fatal("GPE nil")
	}
	if r.GPE.NextProtocolName != "IPv4" {
		t.Errorf("next protocol: %q", r.GPE.NextProtocolName)
	}
	// GPE doesn't have inner Ethernet — should be nil.
	if r.InnerEthernet != nil {
		t.Errorf("GPE shouldn't have inner Ethernet decoded")
	}
}

func TestDecode_NonConformant_NoIFlag(t *testing.T) {
	// Flags = 0x00, I-flag not set, VNI=0xABCDEF.
	// 8-byte header: 00 00 00 00 AB CD EF 00.
	in := "00000000 ABCDEF 00 AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.IFlag {
		t.Errorf("I-flag should be false")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "I-flag") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected I-flag note in: %v", r.Notes)
	}
}

func TestDecode_ReservedNonZero_StandardVXLAN(t *testing.T) {
	// Flags=0x08, Reserved-1 = 0xAABBCC (non-zero, no GBP G/D flag),
	// VNI=5, reserved-2=0. Should classify as standard VXLAN and
	// surface a reserved-non-zero note. 8-byte header: 08 AA BB CC
	// 00 00 05 00.
	in := "08AABBCC 000005 00 AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Variant != "standard VXLAN (RFC 7348)" {
		t.Errorf("variant: %q", r.Variant)
	}
	if r.Reserved1Zero {
		t.Errorf("Reserved1Zero should be false")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Reserved-1") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected Reserved-1 note in: %v", r.Notes)
	}
}

func TestDecode_InnerARP(t *testing.T) {
	// 8-byte header: 08 00 00 00 00 00 0A 00 (VNI=10).
	in := "08000000 00000A 00 FFFFFFFFFFFF 112233445566 0806 0001"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.InnerEthernet == nil ||
		r.InnerEthernet.EtherTypeName != "ARP" {
		t.Errorf("inner ether: %+v", r.InnerEthernet)
	}
}

func TestDecode_GPENextProtocolTable(t *testing.T) {
	cases := map[int]string{
		1: "IPv4", 2: "IPv6", 3: "Ethernet",
		4: "NSH (Network Service Header)", 5: "MPLS",
	}
	for k, v := range cases {
		if got := gpeNextProtocolName(k); got != v {
			t.Errorf("gpeNextProtocolName(%d): got %q want %q", k, got, v)
		}
	}
	if !strings.Contains(gpeNextProtocolName(99), "uncatalogued") {
		t.Errorf("unknown protocol fallback")
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":   "",
		"odd hex": "0800000000ABCDEF0",
		"short":   "0800000000ABCD",
		"bad hex": "ZZ000000 00ABCDEF 00",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
