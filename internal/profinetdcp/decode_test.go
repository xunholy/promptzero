package profinetdcp

import (
	"strings"
	"testing"
)

// TestDecodeIdentifyRequestAll pins a canonical IdentifyAll
// request — the multicast "tell me about everyone" pulse a
// Profinet engineering station sends at boot.
func TestDecodeIdentifyRequestAll(t *testing.T) {
	// FrameID = 0xFEFC IdentifyRequest.
	// Header: serviceID=5 Identify, serviceType=0 Request,
	// xid=0x12345678, responseDelay=1 (× 10 ms × tick factor),
	// dataLength=4 (= one AllSelector block).
	// Block: option=0xFF AllSelector, suboption=0xFF, length=0.
	in := "FEFC " +
		"05 00 12345678 0001 0004 " +
		"FF FF 0000"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FrameIDName != "DCP_Identify_Request" {
		t.Errorf("frameID: got %q want DCP_Identify_Request", r.FrameIDName)
	}
	if r.ServiceIDName != "Identify" || r.ServiceTypeName != "Request" {
		t.Errorf("service: got %s/%s want Identify/Request",
			r.ServiceIDName, r.ServiceTypeName)
	}
	if r.Xid != 0x12345678 {
		t.Errorf("xid: got 0x%X want 0x12345678", r.Xid)
	}
	if len(r.Blocks) != 1 {
		t.Fatalf("blocks: got %d want 1", len(r.Blocks))
	}
	if r.Blocks[0].OptionName != "AllSelector" ||
		r.Blocks[0].SuboptionName != "All" {
		t.Errorf("block: got %s/%s want AllSelector/All",
			r.Blocks[0].OptionName, r.Blocks[0].SuboptionName)
	}
}

// TestDecodeIdentifyResponseStation pins a canonical Identify
// response carrying the station name and device ID.
func TestDecodeIdentifyResponseStation(t *testing.T) {
	// FrameID = 0xFEFB IdentifyResponse.
	// Header: serviceID=5, serviceType=1 Response_Success,
	// xid=0x12345678, responseDelay=0, dataLength = total
	// block bytes.
	//
	// Block 1: Vendor — opt 0x02 / sub 0x01, BlockInfo 0x0001,
	// then "SIEMENS" (7 bytes). length = 2 (BlockInfo) + 7 = 9.
	// On-wire: 02 01 00 09 00 01 53 49 45 4D 45 4E 53 + 1-byte pad
	// (since 9-byte payload + 4-byte header = 13 bytes block,
	// next block needs 16-bit alignment → 1 pad byte).
	//
	// Block 2: NameOfStation — opt 0x02 / sub 0x02, BlockInfo
	// 0x0001, then "et200sp" (7 bytes). length = 9. Pad 1.
	// On-wire: 02 02 00 09 00 01 65 74 32 30 30 73 70 + 1 pad.
	//
	// Block 3: DeviceID — opt 0x02 / sub 0x03, BlockInfo 0x0001,
	// then VendorID=0x002A + DeviceID=0x0100. length = 2 + 4 = 6.
	// On-wire: 02 03 00 06 00 01 00 2A 01 00. No pad (10 bytes
	// even).
	//
	// dataLength = 14 + 14 + 10 = 38 = 0x26.
	in := "FEFB " +
		"05 01 12345678 0000 0026 " +
		"02 01 00 09 00 01 53 49 45 4D 45 4E 53 00 " +
		"02 02 00 09 00 01 65 74 32 30 30 73 70 00 " +
		"02 03 00 06 00 01 00 2A 01 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.FrameIDName != "DCP_Identify_Response" {
		t.Errorf("frameID: got %q want DCP_Identify_Response", r.FrameIDName)
	}
	if len(r.Blocks) != 3 {
		t.Fatalf("blocks: got %d want 3", len(r.Blocks))
	}
	if r.Blocks[0].Vendor != "SIEMENS" {
		t.Errorf("vendor: got %q want SIEMENS", r.Blocks[0].Vendor)
	}
	if r.Blocks[1].NameOfStation != "et200sp" {
		t.Errorf("station: got %q want et200sp", r.Blocks[1].NameOfStation)
	}
	if r.Blocks[2].VendorID != 0x002A {
		t.Errorf("vendorID: got 0x%X want 0x2A", r.Blocks[2].VendorID)
	}
	if r.Blocks[2].DeviceID != 0x0100 {
		t.Errorf("deviceID: got 0x%X want 0x100", r.Blocks[2].DeviceID)
	}
}

// TestDecodeIPParameter pins an IP_Parameter set request.
func TestDecodeIPParameter(t *testing.T) {
	// FrameID Get/Set; serviceID Set; serviceType Request.
	// Block: opt 0x01 / sub 0x02 IP_Parameter, length = 14
	// (2-byte block-qualifier + 12 bytes IP/Mask/GW).
	// BlockQualifier = 0x0001 (Save permanently).
	// IP=192.168.1.10, Mask=255.255.255.0, GW=192.168.1.1.
	in := "FEFD " +
		"04 00 ABCDEF01 0000 0012 " +
		"01 02 000E 0001 C0A8010A FFFFFF00 C0A80101"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ServiceIDName != "Set" {
		t.Errorf("service: got %s want Set", r.ServiceIDName)
	}
	if len(r.Blocks) != 1 {
		t.Fatalf("blocks: got %d want 1", len(r.Blocks))
	}
	bl := r.Blocks[0]
	if bl.OptionName != "IP" || bl.SuboptionName != "IP_Parameter" {
		t.Errorf("opt/sub: got %s/%s", bl.OptionName, bl.SuboptionName)
	}
	if bl.IPAddress != "192.168.1.10" {
		t.Errorf("ip: got %q want 192.168.1.10", bl.IPAddress)
	}
	if bl.SubnetMask != "255.255.255.0" {
		t.Errorf("mask: got %q", bl.SubnetMask)
	}
	if bl.Gateway != "192.168.1.1" {
		t.Errorf("gw: got %q want 192.168.1.1", bl.Gateway)
	}
}

// TestDecodeMACAddress pins the MAC suboption decode.
func TestDecodeMACAddress(t *testing.T) {
	// Block: opt 0x01 / sub 0x01 MAC, length 8 (2-byte
	// BlockInfo + 6-byte MAC). MAC = 00:1B:1B:7C:DE:F0.
	in := "FEFB " +
		"05 01 12345678 0000 000C " +
		"01 01 0008 0001 00 1B 1B 7C DE F0"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Blocks) != 1 {
		t.Fatalf("blocks: got %d want 1", len(r.Blocks))
	}
	if r.Blocks[0].MAC != "00:1B:1B:7C:DE:F0" {
		t.Errorf("mac: got %q want 00:1B:1B:7C:DE:F0", r.Blocks[0].MAC)
	}
}

// TestDecodeDeviceRole pins the DeviceRole bitmask decode.
func TestDecodeDeviceRole(t *testing.T) {
	// Block: opt 0x02 / sub 0x04 DeviceRole, length 4
	// (BlockInfo + 1-byte role + 1-byte reserved).
	// Role = 0x03 = IO-Device + IO-Controller.
	in := "FEFB " +
		"05 01 12345678 0000 0008 " +
		"02 04 0004 0001 03 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Blocks) != 1 {
		t.Fatalf("blocks: got %d want 1", len(r.Blocks))
	}
	bl := r.Blocks[0]
	if bl.DeviceRoleHex != "0x03" {
		t.Errorf("role hex: got %q want 0x03", bl.DeviceRoleHex)
	}
	want := []string{"IO-Device", "IO-Controller"}
	for _, w := range want {
		if !strings.Contains(bl.DeviceRoleDecoded, w) {
			t.Errorf("role decoded missing %q in %q", w, bl.DeviceRoleDecoded)
		}
	}
}

// TestFrameIDNameTable spot-checks the catalogued FrameIDs.
func TestFrameIDNameTable(t *testing.T) {
	cases := map[int]string{
		0xFEFB: "DCP_Identify_Response",
		0xFEFC: "DCP_Identify_Request",
		0xFEFD: "DCP_Get_Set",
		0xFEFE: "DCP_Hello",
	}
	for k, v := range cases {
		if got := frameIDName(k); got != v {
			t.Errorf("frameIDName(0x%04X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(frameIDName(0x1234), "uncatalogued") {
		t.Errorf("frameIDName(0x1234) should mark uncatalogued")
	}
}

// TestServiceIDNameTable spot-checks the catalogued service IDs.
func TestServiceIDNameTable(t *testing.T) {
	cases := map[int]string{
		0x03: "Get", 0x04: "Set",
		0x05: "Identify", 0x06: "Hello",
	}
	for k, v := range cases {
		if got := serviceIDName(k); got != v {
			t.Errorf("serviceIDName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestSuboptionNameTable spot-checks per-option suboption names.
func TestSuboptionNameTable(t *testing.T) {
	if suboptionName(0x01, 0x01) != "MAC" {
		t.Errorf("IP/MAC mislabelled")
	}
	if suboptionName(0x02, 0x02) != "NameOfStation" {
		t.Errorf("DeviceProperties/NameOfStation mislabelled")
	}
	if suboptionName(0x05, 0x03) != "Signal" {
		t.Errorf("ControlBlock/Signal mislabelled")
	}
	if suboptionName(0xFF, 0xFF) != "All" {
		t.Errorf("AllSelector/All mislabelled")
	}
}

// TestDeviceRoleNamesAllBits asserts every documented role bit
// surfaces.
func TestDeviceRoleNamesAllBits(t *testing.T) {
	got := deviceRoleNames(0x0F)
	for _, want := range []string{
		"IO-Device", "IO-Controller", "IO-Multidevice", "PN-Supervisor",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %q", want, got)
		}
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOddNibbles(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("FEFC 05 00 12345678 0000"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 11)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
