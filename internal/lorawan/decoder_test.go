package lorawan

import (
	"strings"
	"testing"
)

// TestDecode_UnconfirmedDataUp pins a minimal Unconfirmed Data
// Up frame:
//
//	MHDR=0x40 (MType=010 Unconfirmed Up, Major=00)
//	DevAddr=01020304 (LE → wire bytes 04 03 02 01)
//	FCtrl=0x80 (ADR=1, FOptsLen=0)
//	FCnt=0x0001 (LE → 01 00)
//	FPort=0x01
//	FRMPayload=AABBCC (encrypted payload, opaque)
//	MIC=11223344
func TestDecode_UnconfirmedDataUp(t *testing.T) {
	got, err := Decode("40 04030201 80 0100 01 AABBCC 11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MHDR.Name != "Unconfirmed Data Up" {
		t.Errorf("MHDR.Name = %q; want 'Unconfirmed Data Up'", got.MHDR.Name)
	}
	if !got.MHDR.Uplink {
		t.Error("Uplink should be true")
	}
	if got.Data == nil {
		t.Fatal("Data field is nil")
	}
	if got.Data.FHDR.DevAddrHex != "01020304" {
		t.Errorf("DevAddrHex = %q; want '01020304' (wire bytes are LE)", got.Data.FHDR.DevAddrHex)
	}
	if !got.Data.FHDR.FCtrl.ADR {
		t.Error("ADR should be true")
	}
	if got.Data.FHDR.FCtrl.FOptsLen != 0 {
		t.Errorf("FOptsLen = %d; want 0", got.Data.FHDR.FCtrl.FOptsLen)
	}
	if got.Data.FHDR.FCnt != 1 {
		t.Errorf("FCnt = %d; want 1", got.Data.FHDR.FCnt)
	}
	if got.Data.FPort == nil || *got.Data.FPort != 1 {
		t.Errorf("FPort = %v; want 1", got.Data.FPort)
	}
	if got.Data.FRMPayloadHex != "AABBCC" {
		t.Errorf("FRMPayloadHex = %q; want 'AABBCC'", got.Data.FRMPayloadHex)
	}
	if got.MICHex != "11223344" {
		t.Errorf("MICHex = %q; want '11223344'", got.MICHex)
	}
}

// TestDecode_ConfirmedDataDown_FCtrlFlags exercises the downlink
// FCtrl interpretation (FPending replaces ClassB, no ADRACKReq).
// Frame: confirmed down, ADR=1, ACK=1, FPending=1, FOptsLen=2.
func TestDecode_ConfirmedDataDown_FCtrlFlags(t *testing.T) {
	// MHDR=0xA0 (101 Confirmed Down, Major=0)
	// DevAddr LE 04 03 02 01
	// FCtrl = ADR(0x80) | ACK(0x20) | FPending(0x10) | FOptsLen(2) = 0xB2
	// FCnt = 0x00 0x00
	// FOpts = AA BB (2 bytes)
	// FPort = 5
	// FRMPayload = CC
	// MIC = 11 22 33 44
	got, err := Decode("A0 04030201 B2 0000 AABB 05 CC 11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MHDR.Name != "Confirmed Data Down" {
		t.Errorf("MHDR.Name = %q", got.MHDR.Name)
	}
	if got.MHDR.Uplink {
		t.Error("Uplink should be false for downlink")
	}
	fc := got.Data.FHDR.FCtrl
	if !fc.ADR || !fc.ACK || !fc.FPending || fc.FOptsLen != 2 {
		t.Errorf("FCtrl = %+v; want ADR=true ACK=true FPending=true FOptsLen=2", fc)
	}
	if fc.ADRACKReq || fc.ClassB {
		t.Errorf("uplink-only flags set on downlink: ADRACKReq=%v ClassB=%v",
			fc.ADRACKReq, fc.ClassB)
	}
	if got.Data.FHDR.FOptsHex != "AABB" {
		t.Errorf("FOptsHex = %q; want 'AABB'", got.Data.FHDR.FOptsHex)
	}
}

// TestDecode_JoinRequest pins the structural Join Request decode
// with the documented little-endian EUI rendering.
//
// Wire bytes:
//
//	JoinEUI LE: 08 07 06 05 04 03 02 01 (→ big-endian "0102030405060708")
//	DevEUI  LE: 10 0F 0E 0D 0C 0B 0A 09 (→ "090A0B0C0D0E0F10")
//	DevNonce LE: 78 56 (= 0x5678)
func TestDecode_JoinRequest(t *testing.T) {
	// MHDR = 0x00 (Join Request, Major=0)
	// 8 + 8 + 2 = 18 bytes payload + 4 MIC = 22 bytes + 1 MHDR = 23
	got, err := Decode("00" +
		"0807060504030201" +
		"100F0E0D0C0B0A09" +
		"7856" +
		"11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MHDR.Name != "Join Request" {
		t.Errorf("MHDR.Name = %q", got.MHDR.Name)
	}
	if got.JoinRequest == nil {
		t.Fatal("JoinRequest is nil")
	}
	if got.JoinRequest.JoinEUIHex != "0102030405060708" {
		t.Errorf("JoinEUIHex = %q; want '0102030405060708' (LE-on-wire → BE)",
			got.JoinRequest.JoinEUIHex)
	}
	if got.JoinRequest.DevEUIHex != "090A0B0C0D0E0F10" {
		t.Errorf("DevEUIHex = %q; want '090A0B0C0D0E0F10'", got.JoinRequest.DevEUIHex)
	}
	if got.JoinRequest.DevNonce != 0x5678 {
		t.Errorf("DevNonce = 0x%X; want 0x5678", got.JoinRequest.DevNonce)
	}
}

// TestDecode_JoinAccept_NoCFList pins the 12-byte (no CFList)
// Join Accept structural decode.
//
// Wire bytes:
//
//	AppNonce LE: 03 02 01 → BE "010203"
//	NetID    LE: 06 05 04 → BE "040506"
//	DevAddr  LE: 0A 09 08 07 → BE "0708090A"
//	DLSettings: 0x12
//	RxDelay:    0x03
func TestDecode_JoinAccept_NoCFList(t *testing.T) {
	got, err := Decode("20" +
		"030201" +
		"060504" +
		"0A090807" +
		"12" +
		"03" +
		"11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MHDR.Name != "Join Accept" {
		t.Errorf("MHDR.Name = %q", got.MHDR.Name)
	}
	if got.JoinAccept == nil {
		t.Fatal("JoinAccept is nil")
	}
	if got.JoinAccept.AppNonceHex != "010203" {
		t.Errorf("AppNonceHex = %q; want '010203'", got.JoinAccept.AppNonceHex)
	}
	if got.JoinAccept.DevAddrHex != "0708090A" {
		t.Errorf("DevAddrHex = %q", got.JoinAccept.DevAddrHex)
	}
	if got.JoinAccept.DLSettings != 0x12 || got.JoinAccept.RxDelay != 0x03 {
		t.Errorf("DLSettings=0x%X RxDelay=0x%X", got.JoinAccept.DLSettings, got.JoinAccept.RxDelay)
	}
	if got.JoinAccept.CFListHex != "" {
		t.Errorf("CFListHex should be empty for 12-byte Join Accept; got %q",
			got.JoinAccept.CFListHex)
	}
}

// TestDecode_JoinAccept_WithCFList exercises the 28-byte form.
func TestDecode_JoinAccept_WithCFList(t *testing.T) {
	cfList := "00112233445566778899AABBCCDDEEFF"
	got, err := Decode("20" +
		"030201" +
		"060504" +
		"0A090807" +
		"12" +
		"03" +
		cfList +
		"11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.JoinAccept.CFListHex != cfList {
		t.Errorf("CFListHex = %q; want %q", got.JoinAccept.CFListHex, cfList)
	}
}

// TestDecode_FCntLittleEndian — confirm FCnt is read little-
// endian per spec.
func TestDecode_FCntLittleEndian(t *testing.T) {
	// FCnt wire bytes 34 12 → host value 0x1234
	got, err := Decode("40 04030201 80 3412 01 AA 11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Data.FHDR.FCnt != 0x1234 {
		t.Errorf("FCnt = 0x%X; want 0x1234", got.Data.FHDR.FCnt)
	}
}

// TestDecode_NoFRMPayload — when FRMPayload is empty, FPort is
// also omitted per spec; the decoder leaves both nil.
func TestDecode_NoFRMPayload(t *testing.T) {
	// MHDR + FHDR (7) + MIC (4) = 12 bytes, no FPort
	got, err := Decode("40 04030201 80 0001 11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.Data.FPort != nil {
		t.Errorf("FPort = %v; want nil for empty FRMPayload", got.Data.FPort)
	}
	if got.Data.FRMPayloadHex != "" {
		t.Errorf("FRMPayloadHex = %q; want empty", got.Data.FRMPayloadHex)
	}
}

// TestDecode_RejoinRequest — MType 6 surfaces as RejoinRequestHex.
func TestDecode_RejoinRequest(t *testing.T) {
	// MHDR 0xC0 (110 Rejoin, Major=00)
	// Rejoin Request payload (variable; we just check structural surfacing)
	got, err := Decode("C0 00112233445566 11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MHDR.Name != "Rejoin Request" {
		t.Errorf("MHDR.Name = %q", got.MHDR.Name)
	}
	if got.RejoinRequestHex == "" {
		t.Error("RejoinRequestHex should be populated")
	}
}

// TestDecode_Proprietary — MType 7 surfaces as ProprietaryHex.
func TestDecode_Proprietary(t *testing.T) {
	got, err := Decode("E0 DEADBEEF 11223344")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.MHDR.Name != "Proprietary" {
		t.Errorf("MHDR.Name = %q", got.MHDR.Name)
	}
	if got.ProprietaryHex != "DEADBEEF" {
		t.Errorf("ProprietaryHex = %q", got.ProprietaryHex)
	}
}

// TestDecode_TruncatedFrame — frame shorter than 5-byte minimum
// (MHDR + MIC).
func TestDecode_TruncatedFrame(t *testing.T) {
	_, err := Decode("40 01")
	if err == nil {
		t.Fatal("want error for truncated frame")
	}
}

// TestDecode_JoinRequestBadLength — Join Request payload that's
// not exactly 18 bytes.
func TestDecode_JoinRequestBadLength(t *testing.T) {
	// 17-byte Join Request payload (one byte short) + 4-byte MIC
	_, err := Decode("00 010203040506070809 0A0B0C0D0E0F1011 11223344")
	if err == nil {
		t.Fatal("want error for short Join Request")
	}
	if !strings.Contains(err.Error(), "Join Request") {
		t.Errorf("err = %v; want it to mention Join Request", err)
	}
}

// TestDecode_DataFOptsTooLong — FCtrl declares more FOpts bytes
// than the MACPayload contains.
func TestDecode_DataFOptsTooLong(t *testing.T) {
	// FCtrl = ADR(0x80) | FOptsLen=15 = 0x8F, but only 0 FOpts bytes follow
	_, err := Decode("40 04030201 8F 0001 11223344")
	if err == nil {
		t.Fatal("want error for over-declared FOptsLen")
	}
}

// TestDecode_EmptyAndInvalidHex — input validation.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_ToleratesSeparators — ':' / '-' / '_' / whitespace.
func TestDecode_ToleratesSeparators(t *testing.T) {
	for _, in := range []string{
		"40:04:03:02:01:80:01:00:01:AA:BB:CC:11:22:33:44",
		"40-04-03-02-01-80-01-00-01-AA-BB-CC-11-22-33-44",
		"  40 04 03 02 01 80 01 00 01 AA BB CC 11 22 33 44  ",
	} {
		got, err := Decode(in)
		if err != nil {
			t.Errorf("Decode(%q): %v", in, err)
			continue
		}
		if got.Data.FHDR.DevAddrHex != "01020304" {
			t.Errorf("Decode(%q): DevAddrHex = %v", in, got.Data.FHDR.DevAddrHex)
		}
	}
}

// TestMTypeNames pins every MType name.
func TestMTypeNames(t *testing.T) {
	cases := map[MType]string{
		MTypeJoinRequest:         "Join Request",
		MTypeJoinAccept:          "Join Accept",
		MTypeUnconfirmedDataUp:   "Unconfirmed Data Up",
		MTypeUnconfirmedDataDown: "Unconfirmed Data Down",
		MTypeConfirmedDataUp:     "Confirmed Data Up",
		MTypeConfirmedDataDown:   "Confirmed Data Down",
		MTypeRejoinRequest:       "Rejoin Request",
		MTypeProprietary:         "Proprietary",
	}
	for v, want := range cases {
		if got := v.String(); got != want {
			t.Errorf("MType(%d).String() = %q; want %q", v, got, want)
		}
	}
}

// TestMTypeIsUplink — the uplink classification driving FCtrl
// interpretation.
func TestMTypeIsUplink(t *testing.T) {
	uplinks := []MType{
		MTypeJoinRequest, MTypeUnconfirmedDataUp,
		MTypeConfirmedDataUp, MTypeRejoinRequest,
	}
	for _, m := range uplinks {
		if !m.IsUplink() {
			t.Errorf("MType %d (%q) should be uplink", m, m.String())
		}
	}
	downlinks := []MType{
		MTypeJoinAccept, MTypeUnconfirmedDataDown,
		MTypeConfirmedDataDown, MTypeProprietary,
	}
	for _, m := range downlinks {
		if m.IsUplink() {
			t.Errorf("MType %d (%q) should NOT be uplink", m, m.String())
		}
	}
}
