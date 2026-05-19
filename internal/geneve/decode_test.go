package geneve

import (
	"strings"
	"testing"
)

func TestDecode_BasicGeneve_TEB(t *testing.T) {
	// No options, ProtocolType=TEB, VNI=0x123456, inner Ethernet
	// with EtherType IPv4. 8-byte header: 00 00 65 58 12 34 56 00.
	in := "00006558 123456 00 AABBCCDDEEFF 112233445566 0800 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 0 {
		t.Errorf("version: %d", r.Version)
	}
	if r.OptionLengthBytes != 0 {
		t.Errorf("option length: %d", r.OptionLengthBytes)
	}
	if r.ProtocolName != "Transparent Ethernet Bridging" {
		t.Errorf("protocol: %q", r.ProtocolName)
	}
	if r.VNI != 0x123456 {
		t.Errorf("VNI: 0x%06X", r.VNI)
	}
	if r.OAM || r.Critical {
		t.Errorf("flags: OAM=%v Critical=%v", r.OAM, r.Critical)
	}
	if r.InnerEthernet == nil {
		t.Fatal("InnerEthernet nil")
	}
	if r.InnerEthernet.DstMAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("dst MAC: %q", r.InnerEthernet.DstMAC)
	}
	if r.InnerEthernet.EtherTypeName != "IPv4" {
		t.Errorf("inner ether: %q", r.InnerEthernet.EtherTypeName)
	}
}

func TestDecode_OneOption_Linux(t *testing.T) {
	// OptionLength = 1 word (4 bytes), one empty option of class
	// 0x0100 (Linux/OVS), type 0x01.
	in := "01006558 000064 00 01000100 AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OptionCount != 1 {
		t.Fatalf("expected 1 option, got %d", r.OptionCount)
	}
	opt := r.Options[0]
	if opt.Class != 0x0100 {
		t.Errorf("class: 0x%04X", opt.Class)
	}
	if opt.ClassName != "Linux / Open vSwitch / OVN" {
		t.Errorf("class name: %q", opt.ClassName)
	}
	if opt.TypeInClass != 1 || opt.CFlag {
		t.Errorf("type: %d critical=%v", opt.TypeInClass, opt.CFlag)
	}
	if opt.LengthBytes != 0 {
		t.Errorf("length: %d", opt.LengthBytes)
	}
}

func TestDecode_CriticalOption(t *testing.T) {
	// C-flag set on the header AND on the option.
	// byte 1 = 0x40 (C=1 in flags), option type 0x80 (C=1).
	in := "01406558 000001 00 01018000 AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.Critical {
		t.Errorf("critical flag should be set")
	}
	if !r.Options[0].CFlag {
		t.Errorf("option critical bit should be set")
	}
	if r.Options[0].TypeInClass != 0 {
		t.Errorf("type-in-class: %d", r.Options[0].TypeInClass)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Critical options present") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected critical-options note in: %v", r.Notes)
	}
}

func TestDecode_OAMPacket_IPv4Inner(t *testing.T) {
	// O-flag set (byte 1 = 0x80), ProtocolType=IPv4. No options.
	in := "00800800 000005 00 4500001C ABCD0000 4011AAAA C0A80101 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.OAM {
		t.Errorf("OAM flag should be set")
	}
	if r.ProtocolName != "IPv4" {
		t.Errorf("protocol: %q", r.ProtocolName)
	}
	// IPv4 inner — no Ethernet peek, just raw payload hex.
	if r.InnerEthernet != nil {
		t.Errorf("IPv4 inner shouldn't have Ethernet peek")
	}
	if r.PayloadHex == "" {
		t.Errorf("expected payload hex for IPv4 inner")
	}
}

func TestDecode_MultipleOptions(t *testing.T) {
	// 3 empty options (4 bytes each = 12 bytes = 3 words).
	// Classes 0x0100 / 0x0101 / 0x0103.
	in := "03006558 000064 00 01000100 01010200 01030300 AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OptionCount != 3 {
		t.Fatalf("expected 3 options, got %d", r.OptionCount)
	}
	wantClasses := []int{0x0100, 0x0101, 0x0103}
	for i, want := range wantClasses {
		if r.Options[i].Class != want {
			t.Errorf("option %d class: 0x%04X want 0x%04X",
				i, r.Options[i].Class, want)
		}
	}
}

func TestDecode_OptionWithData(t *testing.T) {
	// 1 option with 8 bytes of data: Length=2 words (8 bytes).
	// Total option = 4 (header) + 8 (data) = 12 bytes = 3 words.
	in := "03006558 000064 00 0100 1002 DEADBEEFCAFEBABE AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.OptionCount != 1 {
		t.Fatalf("expected 1 option, got %d", r.OptionCount)
	}
	opt := r.Options[0]
	if opt.LengthBytes != 8 {
		t.Errorf("length: %d", opt.LengthBytes)
	}
	if opt.DataHex != "DEADBEEFCAFEBABE" {
		t.Errorf("option data: %q", opt.DataHex)
	}
}

func TestDecode_IPv4Inner_NoEthernetPeek(t *testing.T) {
	// ProtocolType=IPv4; should surface raw payload hex.
	in := "00000800 000064 00 4500001C ABCD0000 4011AAAA C0A80101 C0A80102"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ProtocolName != "IPv4" {
		t.Errorf("protocol: %q", r.ProtocolName)
	}
	if r.InnerEthernet != nil {
		t.Errorf("IPv4 inner shouldn't have Ethernet peek")
	}
	if !strings.Contains(r.PayloadHex, "4500001C") {
		t.Errorf("expected payload to contain IPv4 header start, got %q", r.PayloadHex)
	}
}

func TestDecode_VersionMismatchNote(t *testing.T) {
	// byte 0 = 0x80 → Version=2, OptionLength=0.
	in := "80006558 000064 00 AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 {
		t.Errorf("version: %d", r.Version)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "Version is 2") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected version mismatch note in: %v", r.Notes)
	}
}

func TestDecode_ReservedFlagBitsNonZero(t *testing.T) {
	// byte 1 = 0x01 (reserved bit set).
	in := "00016558 000064 00 AABBCCDDEEFF 112233445566 0800"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Reserved1Zero {
		t.Errorf("Reserved1Zero should be false")
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "reserved bits in flags byte non-zero") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected reserved-bits note in: %v", r.Notes)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":            "",
		"odd hex":          "0000655812345600A",
		"header truncated": "00006558",
		"option overrun":   "01006558 000064 00", // declares 4 bytes of options but only header
		"bad hex":          "ZZ006558 000064 00",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
