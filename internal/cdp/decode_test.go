package cdp

import (
	"strings"
	"testing"
)

func TestDecode_Minimal_DeviceID(t *testing.T) {
	// Header v=2 TTL=180 checksum=0, single TLV Device ID="Switch1".
	// Device ID TLV: 0001 000B "Switch1" (4 hdr + 7 body = 11).
	in := "02 B4 0000 0001 000B 53776974636831"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Version != 2 || r.TTLSeconds != 180 {
		t.Errorf("header: v=%d ttl=%d", r.Version, r.TTLSeconds)
	}
	if r.TLVCount != 1 {
		t.Fatalf("expected 1 TLV, got %d", r.TLVCount)
	}
	if r.TLVs[0].TypeName != "Device ID" {
		t.Errorf("type: %q", r.TLVs[0].TypeName)
	}
	if r.TLVs[0].DeviceID != "Switch1" {
		t.Errorf("device id: %q", r.TLVs[0].DeviceID)
	}
}

func TestDecode_DeviceID_Capabilities_SoftwareVersion(t *testing.T) {
	// Switch with Layer 2 capability + IOS version banner.
	in := "02 B4 0000" +
		"0001 000B 53776974636831" + // Device ID "Switch1"
		"0004 0008 00000008" + //         Capabilities = Switch
		"0005 0012 43697363 6F20494F 5320 31322E32" // Software Version "Cisco IOS 12.2"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TLVCount != 3 {
		t.Fatalf("expected 3 TLVs, got %d", r.TLVCount)
	}
	c := r.TLVs[1].Capabilities
	if c == nil {
		t.Fatal("Capabilities nil")
	}
	if c.Raw != 0x08 {
		t.Errorf("raw: 0x%X", c.Raw)
	}
	if c.Flags != "Switch (Layer 2)" {
		t.Errorf("flags: %q", c.Flags)
	}
	if r.TLVs[2].SoftwareVersion != "Cisco IOS 12.2" {
		t.Errorf("software_version: %q", r.TLVs[2].SoftwareVersion)
	}
}

func TestDecode_Addresses_IPv4(t *testing.T) {
	// Address TLV: 1 entry, NLPID 0xCC, 192.168.1.1.
	in := "02 B4 0000" +
		"0001 0008 51323232" + // Device ID "Q222"
		"0002 0011 00000001 01 01 CC 0004 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var al *AddressList
	for _, tlv := range r.TLVs {
		if tlv.Addresses != nil {
			al = tlv.Addresses
		}
	}
	if al == nil {
		t.Fatal("Addresses TLV not found")
	}
	if al.Count != 1 || len(al.Addresses) != 1 {
		t.Fatalf("address count: declared=%d decoded=%d", al.Count, len(al.Addresses))
	}
	a := al.Addresses[0]
	if a.ProtocolName != "IPv4 (NLPID 0xCC)" {
		t.Errorf("protocol name: %q", a.ProtocolName)
	}
	if a.Address != "192.168.1.1" {
		t.Errorf("address: %q", a.Address)
	}
}

func TestDecode_PortID_Platform(t *testing.T) {
	// Port ID "Gi0/1" + Platform "cisco WS-C2960".
	in := "02 B4 0000" +
		"0003 0009 47 69 30 2F 31" + // Port ID "Gi0/1" (5 bytes body)
		"0006 0012 63697363 6F20 57532D 4332393630" // Platform "cisco WS-C2960" (14 bytes body)
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var portID, platform string
	for _, tlv := range r.TLVs {
		if tlv.PortID != "" {
			portID = tlv.PortID
		}
		if tlv.Platform != "" {
			platform = tlv.Platform
		}
	}
	if portID != "Gi0/1" {
		t.Errorf("port id: %q", portID)
	}
	if platform != "cisco WS-C2960" {
		t.Errorf("platform: %q", platform)
	}
}

func TestDecode_NativeVLAN_Duplex_MTU(t *testing.T) {
	// Native VLAN 100, Duplex full, MTU 1500.
	in := "02 B4 0000" +
		"000A 0006 0064" + //              Native VLAN = 100
		"000B 0005 01" + //                Duplex = full
		"0011 0008 000005DC" //            MTU = 1500
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	var nv *uint16
	var dup string
	var mtu *uint32
	for _, tlv := range r.TLVs {
		if tlv.NativeVLAN != nil {
			nv = tlv.NativeVLAN
		}
		if tlv.Duplex != "" {
			dup = tlv.Duplex
		}
		if tlv.MTU != nil {
			mtu = tlv.MTU
		}
	}
	if nv == nil || *nv != 100 {
		t.Errorf("native_vlan: %+v", nv)
	}
	if dup != "full-duplex" {
		t.Errorf("duplex: %q", dup)
	}
	if mtu == nil || *mtu != 1500 {
		t.Errorf("mtu: %+v", mtu)
	}
}

func TestDecode_CapabilityFlagsTable(t *testing.T) {
	// All 10 documented bits set.
	got := capabilityFlagsName(0x3FF)
	for _, want := range []string{
		"Router", "Transparent Bridge", "Source Route Bridge", "Switch",
		"Host", "IGMP-capable", "Repeater", "VoIP Phone",
		"Remotely Managed Device", "CVTA",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("0x3FF missing %q in %q", want, got)
		}
	}
	if capabilityFlagsName(0) != "(none)" {
		t.Errorf("zero: %q", capabilityFlagsName(0))
	}
}

func TestDecode_Summary(t *testing.T) {
	// Device ID "IS1" (3 bytes body, length 4+3=7=0x0007) +
	// Platform "cygnet" (6 bytes body, length 4+6=10=0x000A).
	in := "02 B4 0000" +
		"0001 0007 495331" +
		"0006 000A 6379676E6574"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Summary != "Device ID + Platform" {
		t.Errorf("summary: %q", r.Summary)
	}
}

func TestDecode_Rejections(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"odd hex":        "02B400",
		"header only":    "02B4",
		"tlv truncated":  "02B40000 0001 000B 5377",
		"tlv bad length": "02B40000 0001 0003 41", // length < 4
		"bad hex":        "ZZB40000",
	}
	for name, in := range cases {
		_, err := Decode(in)
		if err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}

func TestDecode_TLVTypeName(t *testing.T) {
	cases := map[int]string{
		0x0001: "Device ID",
		0x0002: "Addresses",
		0x0004: "Capabilities",
		0x0005: "Software Version",
		0x0006: "Platform",
		0x000A: "Native VLAN",
		0x000B: "Duplex",
		0x0011: "MTU",
		0x0014: "System Name",
		0x0016: "Management Address",
	}
	for k, v := range cases {
		if got := tlvTypeName(k); got != v {
			t.Errorf("tlvTypeName(0x%04X): got %q want %q", k, got, v)
		}
	}
	if !strings.Contains(tlvTypeName(0xFFFF), "uncatalogued") {
		t.Error("unknown TLV fallback")
	}
}
