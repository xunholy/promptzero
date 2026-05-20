package enip

import (
	"strings"
	"testing"
)

// TestDecodeRegisterSession pins a canonical RegisterSession
// command — establishes a TCP/44818 session prior to any
// SendRRData traffic.
func TestDecodeRegisterSession(t *testing.T) {
	// Command=0x0065, Length=4, Session=0, Status=0,
	// SenderContext=00..00, Options=0. Body: Protocol Version
	// 0x0001 + Options Flags 0x0000.
	in := "65 00 04 00 00 00 00 00 00 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00 " +
		"01 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Command != 0x0065 || r.CommandName != "RegisterSession" {
		t.Errorf("command: got 0x%X / %q want 0x0065 / RegisterSession",
			r.Command, r.CommandName)
	}
	if r.Length != 4 {
		t.Errorf("length: got %d want 4", r.Length)
	}
	if r.StatusName != "Success" {
		t.Errorf("status: got %q want Success", r.StatusName)
	}
	if r.PayloadHex != "01000000" {
		t.Errorf("payload: got %q want 01000000", r.PayloadHex)
	}
}

// TestDecodeSendRRDataUnconnectedDataItem pins a SendRRData
// command carrying an Unconnected_Data CIP request — the
// universal shape for explicit-message tag reads.
func TestDecodeSendRRDataUnconnectedDataItem(t *testing.T) {
	// Encapsulation: cmd=0x006F, len=0x16 (22 bytes body),
	// session=0x01020304, status=0, context=8 zero, options=0.
	header := "6F 00 16 00 04 03 02 01 00 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00"
	// Body: interfaceHandle=0, timeout=5, itemCount=2,
	// item1: type=0x0000 Null, length=0;
	// item2: type=0x00B2 Unconnected_Data, length=10:
	//   service=0x0E Get_Attribute_Single (request), pathSize=4
	//   (4 words = 8 bytes), path=20 04 24 01 30 01 — typical
	//   class 4 / instance 1 / attribute 1 EPATH for Connection
	//   Manager, but for the test let's keep it simple: 6 path
	//   bytes (3 words → pathSize=3) + 1 body byte.
	body := "00 00 00 00 05 00 " + // interfaceHandle + timeout
		"02 00 " + // itemCount
		"00 00 00 00 " + // Null item
		"B2 00 0A 00 " + // Unconnected_Data type + length=10
		"0E 03 " + // service code + path size in words
		"20 04 24 01 30 01 " + // 6 bytes of path
		"AA BB" // 2 trailing body bytes
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandName != "SendRRData" {
		t.Errorf("command: got %q want SendRRData", r.CommandName)
	}
	if r.SessionHandle != 0x01020304 {
		t.Errorf("session: got 0x%X want 0x01020304", r.SessionHandle)
	}
	if r.Timeout != 5 {
		t.Errorf("timeout: got %d want 5", r.Timeout)
	}
	if r.ItemCount != 2 {
		t.Errorf("item count: got %d want 2", r.ItemCount)
	}
	if len(r.Items) != 2 {
		t.Fatalf("items: got %d want 2", len(r.Items))
	}
	if r.Items[0].TypeName != "Null" {
		t.Errorf("item0: got %q want Null", r.Items[0].TypeName)
	}
	if r.Items[1].TypeName != "Unconnected_Data" {
		t.Errorf("item1: got %q want Unconnected_Data", r.Items[1].TypeName)
	}
	if r.Items[1].CIP == nil {
		t.Fatal("item1 CIP nil")
	}
	cip := r.Items[1].CIP
	if cip.ServiceCode != 0x0E || cip.ServiceName != "Get_Attribute_Single" {
		t.Errorf("cip service: got 0x%X / %q want 0x0E / Get_Attribute_Single",
			cip.ServiceCode, cip.ServiceName)
	}
	if cip.IsResponse {
		t.Errorf("expected request, got response")
	}
	if cip.PathSizeWords != 3 {
		t.Errorf("path size: got %d want 3", cip.PathSizeWords)
	}
	if cip.PathHex != "200424013001" {
		t.Errorf("path hex: got %q want 200424013001", cip.PathHex)
	}
	if cip.BodyHex != "AABB" {
		t.Errorf("body hex: got %q want AABB", cip.BodyHex)
	}
}

// TestDecodeCIPResponse pins a CIP response with general status
// + additional status.
func TestDecodeCIPResponse(t *testing.T) {
	// Same envelope; CIP item carries:
	//   service=0x8E (Get_Attribute_Single response — high bit set)
	//   reserved=0; generalStatus=0x14 Attribute_Not_Supported
	//   addStatusSize=0; body=empty.
	header := "6F 00 12 00 04 03 02 01 00 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00"
	body := "00 00 00 00 05 00 " +
		"02 00 " +
		"00 00 00 00 " +
		"B2 00 04 00 " +
		"8E 00 14 00"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Items) != 2 {
		t.Fatalf("items: got %d want 2", len(r.Items))
	}
	cip := r.Items[1].CIP
	if cip == nil {
		t.Fatal("cip nil")
	}
	if !cip.IsResponse {
		t.Errorf("expected response")
	}
	if cip.ServiceCode != 0x0E {
		t.Errorf("service code after stripping response bit: got 0x%X want 0x0E",
			cip.ServiceCode)
	}
	if cip.GeneralStatus != 0x14 {
		t.Errorf("general status: got 0x%X want 0x14", cip.GeneralStatus)
	}
	if cip.GeneralStatusName != "Attribute_Not_Supported" {
		t.Errorf("general status name: got %q", cip.GeneralStatusName)
	}
}

// TestDecodeListIdentity pins a ListIdentity broadcast command.
func TestDecodeListIdentity(t *testing.T) {
	in := "63 00 00 00 00 00 00 00 00 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CommandName != "ListIdentity" {
		t.Errorf("command: got %q want ListIdentity", r.CommandName)
	}
}

// TestDecodeStatusInvalidSession pins a non-zero status response.
func TestDecodeStatusInvalidSession(t *testing.T) {
	// Status = 0x00000064 Invalid_Session_Handle.
	in := "6F 00 00 00 04 03 02 01 64 00 00 00 " +
		"00 00 00 00 00 00 00 00 00 00 00 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.StatusName != "Invalid_Session_Handle" {
		t.Errorf("status: got %q want Invalid_Session_Handle", r.StatusName)
	}
}

// TestCommandNameTable spot-checks each catalogued command.
func TestCommandNameTable(t *testing.T) {
	cases := map[int]string{
		0x0000: "NOP", 0x0004: "ListServices",
		0x0063: "ListIdentity", 0x0064: "ListInterfaces",
		0x0065: "RegisterSession", 0x0066: "UnRegisterSession",
		0x006F: "SendRRData", 0x0070: "SendUnitData",
	}
	for k, v := range cases {
		if got := commandName(k); got != v {
			t.Errorf("commandName(0x%04X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(commandName(0xFFFF), "uncatalogued") {
		t.Errorf("commandName(0xFFFF) should mark uncatalogued")
	}
}

// TestCIPServiceNameTable spot-checks the catalogued services.
func TestCIPServiceNameTable(t *testing.T) {
	cases := map[int]string{
		0x01: "Get_Attributes_All",
		0x0E: "Get_Attribute_Single",
		0x4C: "Read_Tag", 0x4D: "Write_Tag",
		0x54: "Forward_Open", 0x5B: "Forward_Close",
	}
	for k, v := range cases {
		if got := cipServiceName(k); got != v {
			t.Errorf("cipServiceName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestCIPGeneralStatusNameTable spot-checks the documented
// general status codes.
func TestCIPGeneralStatusNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "Success", 0x05: "Path_Destination_Unknown",
		0x08: "Service_Not_Supported", 0x0E: "Attribute_Not_Settable",
		0x14: "Attribute_Not_Supported", 0x16: "Object_Does_Not_Exist",
	}
	for k, v := range cases {
		if got := cipGeneralStatusName(k); got != v {
			t.Errorf("cipGeneralStatusName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestItemTypeNameTable spot-checks the documented item types.
func TestItemTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0x0000: "Null", 0x000C: "ListIdentity_item",
		0x00A1: "Connected_Address", 0x00B1: "Connected_Data",
		0x00B2: "Unconnected_Data",
	}
	for k, v := range cases {
		if got := itemTypeName(k); got != v {
			t.Errorf("itemTypeName(0x%04X) = %q want %q", k, got, v)
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
	if _, err := Decode("65 00 00 00"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 23)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
