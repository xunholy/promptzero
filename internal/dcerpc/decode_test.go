package dcerpc

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// header builds a 16-byte DCE/RPC v5.0 common header.
func dcerpcHeader(ptype, pfc byte, fragLen uint16,
	authLen uint16, callID uint32) []byte {
	h := make([]byte, headerSize)
	h[0] = 5
	h[1] = 0
	h[2] = ptype
	h[3] = pfc
	h[4] = 0x10 // drep[0] little-endian
	binary.LittleEndian.PutUint16(h[8:10], fragLen)
	binary.LittleEndian.PutUint16(h[10:12], authLen)
	binary.LittleEndian.PutUint32(h[12:16], callID)
	return h
}

// uuidBytes packs an interface UUID into the 16-byte MS-RPC
// layout (first 3 fields LE, last 2 as BE byte arrays).
func uuidBytes(d1 uint32, d2, d3 uint16, last8 [8]byte) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[0:4], d1)
	binary.LittleEndian.PutUint16(b[4:6], d2)
	binary.LittleEndian.PutUint16(b[6:8], d3)
	copy(b[8:16], last8[:])
	return b
}

func bindBody(interfaceUUID []byte, verMajor, verMinor uint16) []byte {
	body := make([]byte, 12+4+16+4)
	binary.LittleEndian.PutUint16(body[0:2], 4280)
	binary.LittleEndian.PutUint16(body[2:4], 4280)
	binary.LittleEndian.PutUint32(body[4:8], 0)
	body[8] = 1 // p_context_elem_count
	// First p_cont_elem at body[12]:
	//   p_cont_id (2) / n_transfer_syn (1) / reserved (1)
	binary.LittleEndian.PutUint16(body[12:14], 0)
	body[14] = 1 // n_transfer_syn
	copy(body[16:32], interfaceUUID)
	binary.LittleEndian.PutUint16(body[32:34], verMajor)
	binary.LittleEndian.PutUint16(body[34:36], verMinor)
	return body
}

// TestDecodeBindNetlogon pins the ZeroLogon attack signature
// (BIND to netlogon UUID).
func TestDecodeBindNetlogon(t *testing.T) {
	uuid := uuidBytes(0x12345678, 0x1234, 0xabcd,
		[8]byte{0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb})
	body := bindBody(uuid, 1, 0)
	msg := append(dcerpcHeader(11, 0x03, uint16(headerSize+len(body)), 0, 1), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.PTypeName != "BIND" {
		t.Errorf("PTypeName: got %q want BIND", r.PTypeName)
	}
	if r.InterfaceUUID != "12345678-1234-abcd-ef00-01234567cffb" {
		t.Errorf("UUID: got %q", r.InterfaceUUID)
	}
	if !strings.Contains(r.InterfaceName, "netlogon") ||
		!strings.Contains(r.InterfaceName, "ZeroLogon") {
		t.Errorf("InterfaceName should flag netlogon/ZeroLogon, got %q",
			r.InterfaceName)
	}
	if !r.LittleEndian {
		t.Errorf("LittleEndian should be true (drep[0] bit 4 set)")
	}
}

// TestDecodeBindDrsuapi pins the DCSync attack signature.
func TestDecodeBindDrsuapi(t *testing.T) {
	uuid := uuidBytes(0xe3514235, 0x4b06, 0x11d1,
		[8]byte{0xab, 0x04, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2})
	body := bindBody(uuid, 4, 0)
	msg := append(dcerpcHeader(11, 0x03, 0, 0, 2), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.InterfaceName, "DCSync") {
		t.Errorf("InterfaceName should flag DCSync, got %q",
			r.InterfaceName)
	}
}

// TestDecodeBindSpoolss pins the PrintNightmare attack
// signature.
func TestDecodeBindSpoolss(t *testing.T) {
	uuid := uuidBytes(0x12345678, 0x1234, 0xabcd,
		[8]byte{0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab})
	body := bindBody(uuid, 1, 0)
	msg := append(dcerpcHeader(11, 0x03, 0, 0, 3), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(r.InterfaceName, "spoolss") ||
		!strings.Contains(r.InterfaceName, "PrintNightmare") {
		t.Errorf("InterfaceName should flag spoolss/PrintNightmare, got %q",
			r.InterfaceName)
	}
}

// TestDecodeRequest pins the opnum-extraction path.
func TestDecodeRequest(t *testing.T) {
	body := make([]byte, 8)
	binary.LittleEndian.PutUint32(body[0:4], 256)
	binary.LittleEndian.PutUint16(body[4:6], 0)
	binary.LittleEndian.PutUint16(body[6:8], 30) // ZeroLogon target opnum
	msg := append(dcerpcHeader(0, 0x03, 24, 0, 5), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.PTypeName != "REQUEST" {
		t.Errorf("PTypeName: got %q want REQUEST", r.PTypeName)
	}
	if r.Opnum != 30 {
		t.Errorf("Opnum: got %d want 30 (NetrServerAuthenticate3)",
			r.Opnum)
	}
	if r.AllocHint != 256 {
		t.Errorf("AllocHint: got %d want 256", r.AllocHint)
	}
}

// TestDecodeFault pins the fault-status decode + name lookup.
func TestDecodeFault(t *testing.T) {
	body := make([]byte, 12)
	binary.LittleEndian.PutUint32(body[0:4], 0)
	binary.LittleEndian.PutUint16(body[4:6], 0)
	body[6] = 0
	body[7] = 0
	binary.LittleEndian.PutUint32(body[8:12], 0x00000005)
	msg := append(dcerpcHeader(3, 0x03, 28, 0, 6), body...)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.PTypeName != "FAULT" {
		t.Errorf("PTypeName: got %q want FAULT", r.PTypeName)
	}
	if r.FaultStatusName != "nca_s_fault_access_denied" {
		t.Errorf("FaultStatusName: got %q", r.FaultStatusName)
	}
}

// TestDecodePFCFlags pins multi-flag decoding.
func TestDecodePFCFlags(t *testing.T) {
	msg := dcerpcHeader(0, 0x03, 16, 0, 1)
	r, err := Decode(hex.EncodeToString(msg))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.PFCFlagsNames) != 2 {
		t.Errorf("PFCFlagsNames: got %d want 2", len(r.PFCFlagsNames))
	}
	if r.PFCFlagsNames[0] != "FIRST_FRAG" {
		t.Errorf("first flag: got %q", r.PFCFlagsNames[0])
	}
	if r.PFCFlagsNames[1] != "LAST_FRAG" {
		t.Errorf("second flag: got %q", r.PFCFlagsNames[1])
	}
}

// TestPTypeNameTable spot-checks each catalogued PTYPE.
func TestPTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0:  "REQUEST",
		2:  "RESPONSE",
		3:  "FAULT",
		11: "BIND",
		12: "BIND_ACK",
		13: "BIND_NAK",
		14: "ALTER_CONTEXT",
		15: "ALTER_CONTEXT_RESP",
		19: "AUTH3",
	}
	for k, v := range cases {
		if got := ptypeName(k); got != v {
			t.Errorf("ptypeName(%d) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(ptypeName(99), "uncatalogued") {
		t.Errorf("uncatalogued PTYPE should be flagged")
	}
}

// TestInterfaceNameTable spot-checks attack-vector flagging.
func TestInterfaceNameTable(t *testing.T) {
	cases := map[string]string{
		"12345678-1234-abcd-ef00-01234567cffb": "ZeroLogon",
		"e3514235-4b06-11d1-ab04-00c04fc2dcd2": "DCSync",
		"12345678-1234-abcd-ef00-0123456789ab": "PrintNightmare",
		"367abb81-9844-35f1-ad32-98f038001003": "PsExec",
		"1ff70682-0a51-30e8-076d-740be8cee98b": "Task Scheduler",
		"c681d488-d850-11d0-8c52-00c04fd90f7e": "PetitPotam",
	}
	for uuid, marker := range cases {
		got := interfaceName(uuid)
		if !strings.Contains(got, marker) {
			t.Errorf("interfaceName(%s) = %q want contains %q",
				uuid, got, marker)
		}
	}
}

// TestFaultStatusNameTable spot-checks each catalogued fault.
func TestFaultStatusNameTable(t *testing.T) {
	cases := map[uint32]string{
		0x00000005: "nca_s_fault_access_denied",
		0x1C010002: "nca_s_fault_addr_error",
		0x1C010003: "nca_s_fault_context_mismatch",
		0x000006BD: "RPC_X_BAD_STUB_DATA",
	}
	for k, v := range cases {
		if got := faultStatusName(k); got != v {
			t.Errorf("faultStatusName(0x%08X) = %q want %q",
				k, got, v)
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

func TestDecodeRejectsWrongVersion(t *testing.T) {
	b := make([]byte, headerSize)
	b[0] = 4
	if _, err := Decode(hex.EncodeToString(b)); err == nil {
		t.Fatal("want error for non-v5 DCE/RPC")
	}
}
