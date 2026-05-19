package lldp

import (
	"strings"
	"testing"
)

func TestDecode_MinimalLLDPDU(t *testing.T) {
	// Mandatory TLVs: Chassis ID (MAC), Port ID (Interface name
	// "eth0"), TTL=120, End.
	in := "0207 04 001122334455" + // Chassis ID type=1 len=7, subtype 4 MAC
		"0405 05 65746830" + //          Port ID type=2 len=5, subtype 5 Interface name "eth0"
		"0602 0078" + //                  TTL type=3 len=2, 120 seconds
		"0000" //                          End of LLDPDU type=0 len=0
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TLVCount != 4 {
		t.Fatalf("expected 4 TLVs, got %d", r.TLVCount)
	}
	c := r.TLVs[0]
	if c.TypeName != "Chassis ID" {
		t.Errorf("TLV 0: %q", c.TypeName)
	}
	if c.ChassisID == nil || c.ChassisID.SubtypeName != "MAC address" {
		t.Errorf("Chassis subtype: %+v", c.ChassisID)
	}
	if c.ChassisID.MAC != "00:11:22:33:44:55" {
		t.Errorf("MAC: %q", c.ChassisID.MAC)
	}

	p := r.TLVs[1]
	if p.PortID == nil || p.PortID.SubtypeName != "Interface name" {
		t.Errorf("Port subtype: %+v", p.PortID)
	}
	if p.PortID.IDText != "eth0" {
		t.Errorf("port id text: %q", p.PortID.IDText)
	}

	tl := r.TLVs[2]
	if tl.TTLSeconds == nil || *tl.TTLSeconds != 120 {
		t.Errorf("TTL: %+v", tl.TTLSeconds)
	}

	if r.TLVs[3].TypeName != "End of LLDPDU" {
		t.Errorf("end TLV: %q", r.TLVs[3].TypeName)
	}

	if len(r.Notes) != 0 {
		t.Errorf("expected no notes, got %v", r.Notes)
	}
}

func TestDecode_WithSystemNameAndCapabilities(t *testing.T) {
	// Chassis + Port + TTL + System Name "switch1" + Capabilities.
	in := "0207 04 001122334455" +
		"0405 05 65746830" +
		"0602 0078" +
		"0A07 73 77 69 74 63 68 31" + // System Name "switch1"
		"0E04 0014 0010" + //              Capabilities: Router|MAC Bridge, Router enabled
		"0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var foundName, foundCaps bool
	for _, tlv := range r.TLVs {
		if tlv.TypeName == "System Name" && tlv.SystemName == "switch1" {
			foundName = true
		}
		if tlv.TypeName == "System Capabilities" && tlv.Capabilities != nil {
			if !strings.Contains(tlv.Capabilities.CapabilityFlags, "Router") ||
				!strings.Contains(tlv.Capabilities.CapabilityFlags, "MAC Bridge") {
				t.Errorf("capability flags: %q",
					tlv.Capabilities.CapabilityFlags)
			}
			if tlv.Capabilities.EnabledFlags != "Router" {
				t.Errorf("enabled flags: %q", tlv.Capabilities.EnabledFlags)
			}
			foundCaps = true
		}
	}
	if !foundName {
		t.Error("System Name TLV not found / wrong value")
	}
	if !foundCaps {
		t.Error("System Capabilities TLV not found")
	}
}

func TestDecode_ManagementAddress_IPv4(t *testing.T) {
	// Mandatory 3 + Management Address (192.168.1.1, ifIndex 1) + End.
	in := "0207 04 001122334455" +
		"0405 05 65746830" +
		"0602 0078" +
		"100C 05 01 C0A80101 02 00000001 00" +
		"0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var m *ManagementAddress
	for _, tlv := range r.TLVs {
		if tlv.ManagementAddress != nil {
			m = tlv.ManagementAddress
		}
	}
	if m == nil {
		t.Fatal("Management Address TLV not found")
	}
	if m.AddressSubtypeName != "IPv4" {
		t.Errorf("address subtype: %q", m.AddressSubtypeName)
	}
	if m.Address != "192.168.1.1" {
		t.Errorf("address: %q", m.Address)
	}
	if m.InterfaceSubtypeName != "ifIndex" {
		t.Errorf("interface subtype: %q", m.InterfaceSubtypeName)
	}
	if m.InterfaceNumber != 1 {
		t.Errorf("interface number: %d", m.InterfaceNumber)
	}
}

func TestDecode_OrganizationallySpecific_IEEE8021(t *testing.T) {
	// Mandatory 3 + Org Specific (IEEE 802.1 OUI 00-80-C2) + End.
	in := "0207 04 001122334455" +
		"0405 05 65746830" +
		"0602 0078" +
		"FE05 0080C2 01 00" + // type=127 len=5, OUI 00-80-C2, subtype 1, body 00
		"0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var o *OrgSpecific
	for _, tlv := range r.TLVs {
		if tlv.OrgSpecific != nil {
			o = tlv.OrgSpecific
		}
	}
	if o == nil {
		t.Fatal("Org Specific TLV not found")
	}
	if o.OUI != "00-80-C2" {
		t.Errorf("OUI: %q", o.OUI)
	}
	if o.OUIName != "IEEE 802.1" {
		t.Errorf("OUI name: %q", o.OUIName)
	}
	if o.Subtype != 1 {
		t.Errorf("subtype: %d", o.Subtype)
	}
}

func TestDecode_MandatoryOrderingViolation(t *testing.T) {
	// TTL first, then Chassis, then Port — violates §8.1.1.
	in := "0602 0078" +
		"0207 04 001122334455" +
		"0405 05 65746830" +
		"0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(r.Notes) == 0 {
		t.Error("expected ordering note")
	}
}

func TestDecode_Summary(t *testing.T) {
	in := "0207 04 001122334455" +
		"0405 05 65746830" +
		"0602 0078" +
		"0000"
	r, _ := Decode(in)
	if r.Summary != "Chassis ID + Port ID + Time-To-Live + End of LLDPDU" {
		t.Errorf("summary: %q", r.Summary)
	}
}

func TestDecode_EndOfLLDPDUStopsWalker(t *testing.T) {
	// End TLV in the middle — trailing bytes are ignored.
	in := "0207 04 001122334455" +
		"0000" +
		"DEADBEEF" // garbage after End — should be silently dropped
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TLVCount != 2 {
		t.Errorf("expected 2 TLVs (Chassis + End), got %d", r.TLVCount)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":     "",
		"odd hex":   "020",
		"truncated": "0207 04 0011",
		"bad hex":   "ZZ07 04 001122334455",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestCapabilityFlagsTable(t *testing.T) {
	if !strings.Contains(capabilityFlagsName(0x07FF), "Other") {
		t.Error("0x07FF should include Other")
	}
	if !strings.Contains(capabilityFlagsName(0x07FF), "Two-port MAC Relay") {
		t.Error("0x07FF should include Two-port MAC Relay")
	}
	if capabilityFlagsName(0) != "(none)" {
		t.Errorf("zero: %q", capabilityFlagsName(0))
	}
}
