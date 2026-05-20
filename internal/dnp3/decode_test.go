package dnp3

import (
	"strings"
	"testing"
)

// TestDecodeReadRequest pins a master-to-outstation READ request
// (function code 0x01) in a CONFIRMED_USER_DATA link frame.
func TestDecodeReadRequest(t *testing.T) {
	// Data-link header (10 bytes): 0564 LEN CTRL DSTLE SRCLE CRC.
	// LEN = 5 (control + dest + src) + 3 (transport + app
	// control + function) + 2 (single object header bytes) = 10.
	// CTRL = 0xC4 (DIR=1 master→out, PRM=1, FCB=0, FCV=0,
	// fcode=4 — but actually 0xC4 = bits 11000100 = DIR=1,
	// PRM=1, FCB=0, FCV=0, code=0100=4 — use code=4 (none of
	// the defined primary codes; pick code 2 CONFIRMED).
	// CTRL = 0xC2 (DIR=1, PRM=1, FCB=0, FCV=0, code=0x02
	// CONFIRMED_USER_DATA). Dest=0x0064 (100), Src=0x0001 (1).
	// CRC = 0xDEAD placeholder.
	header := "05 64 0A C2 6400 0100 DEAD"
	// User data block: transport=0xC0 (FIN=1, FIR=1, seq=0);
	// app control=0xC1 (FIR=1, FIN=1, CON=0, UNS=0, seq=1);
	// function=0x01 READ; object header bytes 01 3C =
	// group 1 (binary input static), variation 60 (just an
	// example trailing pair). Block CRC = BEEF.
	user := "C0 C1 01 01 3C BEEF"
	r, err := Decode(header + user)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.Length != 10 {
		t.Errorf("length: got %d want 10", r.Length)
	}
	if !r.DIR || !r.PRM {
		t.Errorf("DIR/PRM: got %v/%v want true/true", r.DIR, r.PRM)
	}
	if r.LinkFunctionName != "CONFIRMED_USER_DATA" {
		t.Errorf("linkFunc: got %q want CONFIRMED_USER_DATA", r.LinkFunctionName)
	}
	if r.Destination != 100 || r.Source != 1 {
		t.Errorf("dst/src: got %d/%d want 100/1", r.Destination, r.Source)
	}
	if !r.TransportFIN || !r.TransportFIR || r.TransportSeq != 0 {
		t.Errorf("transport: fin=%v fir=%v seq=%d", r.TransportFIN, r.TransportFIR,
			r.TransportSeq)
	}
	if !r.AppFIR || !r.AppFIN || r.AppSeq != 1 {
		t.Errorf("app control: fir=%v fin=%v seq=%d", r.AppFIR, r.AppFIN, r.AppSeq)
	}
	if r.AppFunctionName != "READ" {
		t.Errorf("appFunc: got %q want READ", r.AppFunctionName)
	}
	if r.ObjectDataHex != "013C" {
		t.Errorf("object data: got %q want 013C", r.ObjectDataHex)
	}
}

// TestDecodeResponseWithIIN pins a RESPONSE function code (0x81)
// with several IIN bits asserted.
func TestDecodeResponseWithIIN(t *testing.T) {
	// Header: outstation → master direction (DIR=0), PRM=1.
	// CTRL = 0x44: bits 01000100 = DIR=0, PRM=1, FCB=0,
	// FCV=0, code=4 — not a standard primary code, so name
	// will be uncatalogued. Use code=3 UNCONFIRMED_USER_DATA
	// — CTRL = 0x43.
	// LEN = 5 (link control + dest + src) + 6 (transport +
	// appCtl + fn + IIN1 + IIN2 + 1 object byte) = 11 (0x0B).
	header := "05 64 0B 43 0100 6400 DEAD"
	// transport=0xC0; appCtl=0xC0 (FIR+FIN, seq 0); fn=0x81
	// RESPONSE; IIN=0x10 0x02 (LE → 0x0210) → IIN1=0x10
	// NEED_TIME, IIN2=0x02 OBJECT_UNKNOWN; object byte 0x00.
	user := "C0 C0 81 10 02 00 BEEF"
	r, err := Decode(header + user)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.DIR {
		t.Errorf("DIR: got true want false")
	}
	if r.LinkFunctionName != "UNCONFIRMED_USER_DATA" {
		t.Errorf("linkFunc: got %q", r.LinkFunctionName)
	}
	if r.AppFunctionName != "RESPONSE" {
		t.Errorf("appFunc: got %q want RESPONSE", r.AppFunctionName)
	}
	if r.IINHex != "0x0210" {
		t.Errorf("iinHex: got %q want 0x0210", r.IINHex)
	}
	if !strings.Contains(r.IINBitsDecoded, "NEED_TIME") ||
		!strings.Contains(r.IINBitsDecoded, "OBJECT_UNKNOWN") {
		t.Errorf("iin decoded: got %q", r.IINBitsDecoded)
	}
	if r.ObjectDataHex != "00" {
		t.Errorf("object data: got %q want 00", r.ObjectDataHex)
	}
}

// TestDecodeUnsolicited pins UNSOLICITED_RESPONSE with UNS bit
// set in the application control byte and DEVICE_RESTART IIN.
func TestDecodeUnsolicited(t *testing.T) {
	// CTRL = 0x44 (DIR=0, PRM=1, code=4) is not standard;
	// use 0x43 UNCONFIRMED_USER_DATA again. LEN = 5 + 5
	// (transport + appCtl + fn + IIN1 + IIN2) = 10 (0x0A).
	header := "05 64 0A 43 0100 6400 DEAD"
	// appCtl=0xD0 (FIR+FIN+UNS, seq 0); fn=0x82 UNSOLICITED;
	// IIN=0x80 0x00 (LE → 0x0080) → IIN1 bit 7 DEVICE_RESTART.
	user := "C0 D0 82 80 00 BEEF"
	r, err := Decode(header + user)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.AppFunctionName != "UNSOLICITED_RESPONSE" {
		t.Errorf("appFunc: got %q want UNSOLICITED_RESPONSE", r.AppFunctionName)
	}
	if !r.AppUNS {
		t.Errorf("AppUNS: got false want true")
	}
	if !strings.Contains(r.IINBitsDecoded, "DEVICE_RESTART") {
		t.Errorf("iin decoded missing DEVICE_RESTART: %q", r.IINBitsDecoded)
	}
}

// TestDecodeLinkStatusOnly pins a pure data-link frame (no user
// data) — REQUEST_LINK_STATUS.
func TestDecodeLinkStatusOnly(t *testing.T) {
	// LEN = 5 (control + dest + src only; no user data).
	// CTRL = 0xC9 (DIR=1, PRM=1, code=9 REQUEST_LINK_STATUS).
	in := "05 64 05 C9 6400 0100 DEAD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.LinkFunctionName != "REQUEST_LINK_STATUS" {
		t.Errorf("linkFunc: got %q want REQUEST_LINK_STATUS", r.LinkFunctionName)
	}
	if r.AppFunctionName != "" {
		t.Errorf("expected no application data, got appFunc=%q", r.AppFunctionName)
	}
}

// TestDecodeMultiBlockUserData pins user data spanning two CRC
// blocks — first block 16 bytes + CRC, second block 4 bytes +
// CRC.
func TestDecodeMultiBlockUserData(t *testing.T) {
	// LEN = 5 + 20 = 25 bytes user data.
	header := "05 64 19 C2 6400 0100 DEAD"
	// Block 1: 16 bytes. Start with transport=0xC0, appCtl=0xC1,
	// fn=0x01 READ, then 13 bytes of "objects" 02 through 0E.
	// Block CRC = 1111.
	block1 := "C0 C1 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 1111"
	// Block 2: 4 bytes 0F 10 11 12 + CRC 2222.
	block2 := "0F 10 11 12 2222"
	r, err := Decode(header + block1 + block2)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.AppFunctionName != "READ" {
		t.Errorf("appFunc: got %q want READ", r.AppFunctionName)
	}
	// User data after stripping CRCs should be 20 bytes:
	// C0 C1 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F 10 11 12
	if r.UserDataHex != "C0C10102030405060708090A0B0C0D0E0F10111 2"[:40] {
		// Build canonical expected
		wantHex := "C0C10102030405060708090A0B0C0D0E0F101112"
		if r.UserDataHex != wantHex {
			t.Errorf("user_data: got %q want %q", r.UserDataHex, wantHex)
		}
	}
	// Object data = everything after transport(1) + appCtl(1) +
	// fn(1) = byte index 3 onward of the 20-byte user-data
	// stream → 17 object bytes 02 03 ... 12.
	wantObj := "02030405060708090A0B0C0D0E0F101112"
	if r.ObjectDataHex != wantObj {
		t.Errorf("object_data: got %q want %q", r.ObjectDataHex, wantObj)
	}
}

// TestAppFunctionNameTable spot-checks the catalogued codes.
func TestAppFunctionNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "CONFIRM", 0x01: "READ", 0x02: "WRITE",
		0x05: "DIRECT_OPERATE", 0x14: "ENABLE_UNSOLICITED",
		0x17: "DELAY_MEASURE", 0x20: "AUTHENTICATE_REQ",
		0x81: "RESPONSE", 0x82: "UNSOLICITED_RESPONSE",
		0x83: "AUTHENTICATE_RESP",
	}
	for k, v := range cases {
		if got := appFunctionName(k); got != v {
			t.Errorf("appFunctionName(0x%02X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(appFunctionName(0xEE), "uncatalogued") {
		t.Errorf("uncatalogued code should be flagged")
	}
}

// TestIINBitDecodes asserts every IIN bit name surfaces.
func TestIINBitDecodes(t *testing.T) {
	// All IIN1 bits set + all IIN2 documented bits set =
	// 0x3FFF.
	dec := iinBitNames(0x3FFF)
	want := []string{
		"BROADCAST", "CLASS_1_EVENTS", "CLASS_2_EVENTS",
		"CLASS_3_EVENTS", "NEED_TIME", "LOCAL_CONTROL",
		"DEVICE_TROUBLE", "DEVICE_RESTART",
		"NO_FUNC_CODE_SUPPORT", "OBJECT_UNKNOWN",
		"PARAMETER_ERROR", "EVENT_BUFFER_OVERFLOW",
		"ALREADY_EXECUTING", "CONFIG_CORRUPT",
	}
	for _, w := range want {
		if !strings.Contains(dec, w) {
			t.Errorf("missing %q in %q", w, dec)
		}
	}
}

// TestLinkFunctionNamePrimaryVsSecondary asserts the name table
// differs for primary vs secondary frames.
func TestLinkFunctionNamePrimaryVsSecondary(t *testing.T) {
	if linkFunctionName(0, true) != "RESET_LINK_STATES" {
		t.Errorf("primary code 0 mislabelled")
	}
	if linkFunctionName(0, false) != "ACK" {
		t.Errorf("secondary code 0 mislabelled")
	}
	if linkFunctionName(11, false) != "LINK_STATUS" {
		t.Errorf("secondary code 11 mislabelled")
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
	if _, err := Decode("05 64 05 C9"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsMissingSync(t *testing.T) {
	if _, err := Decode("0102 05 C9 6400 0100 DEAD"); err == nil {
		t.Fatal("want error when sync bytes 0x05 0x64 missing")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 9)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
