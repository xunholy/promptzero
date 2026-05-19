package bacnet

import (
	"strings"
	"testing"
)

// TestDecode_WhoIsBroadcast pins the canonical BACnet/IP
// Who-Is global broadcast — the most-captured frame on any
// BMS network.
//
//	BVLC: 81 0B 00 0C  (BACnet/IP, Original-Broadcast-NPDU, len 12)
//	NPDU: 01 20 FF FF 00 FF  (v1, dest-spec, global net, no addr, hop 255)
//	APDU: 10 08  (Unconfirmed-Request, service who-Is)
func TestDecode_WhoIsBroadcast(t *testing.T) {
	got, err := Decode("81 0B 00 0C 01 20 FF FF 00 FF 10 08")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.BVLC == nil {
		t.Fatal("BVLC nil")
	}
	if got.BVLC.Function != 0x0B {
		t.Errorf("BVLC.Function = 0x%02X; want 0x0B", got.BVLC.Function)
	}
	if got.BVLC.FunctionName != "Original-Broadcast-NPDU" {
		t.Errorf("BVLC.FunctionName = %q", got.BVLC.FunctionName)
	}
	if got.BVLC.Length != 12 {
		t.Errorf("BVLC.Length = %d; want 12", got.BVLC.Length)
	}
	if got.NPDU == nil {
		t.Fatal("NPDU nil")
	}
	if got.NPDU.Version != 1 {
		t.Errorf("NPDU.Version = %d; want 1", got.NPDU.Version)
	}
	if !got.NPDU.DestSpecifier {
		t.Error("DestSpecifier = false; want true")
	}
	if got.NPDU.DestNetwork == nil || *got.NPDU.DestNetwork != 0xFFFF {
		t.Errorf("DestNetwork = %v; want 0xFFFF (global)", got.NPDU.DestNetwork)
	}
	if got.NPDU.DestAddressHex != "" {
		t.Errorf("DestAddressHex = %q; want empty (broadcast)", got.NPDU.DestAddressHex)
	}
	if got.NPDU.HopCount == nil || *got.NPDU.HopCount != 255 {
		t.Errorf("HopCount = %v; want 255", got.NPDU.HopCount)
	}
	if got.APDU == nil {
		t.Fatal("APDU nil")
	}
	if got.APDU.PDUType != 1 {
		t.Errorf("PDUType = %d; want 1 (Unconfirmed-Request)", got.APDU.PDUType)
	}
	if got.APDU.PDUTypeName != "Unconfirmed-Request-PDU" {
		t.Errorf("PDUTypeName = %q", got.APDU.PDUTypeName)
	}
	if got.APDU.ServiceChoice == nil || *got.APDU.ServiceChoice != 8 {
		t.Errorf("ServiceChoice = %v; want 8 (who-Is)", got.APDU.ServiceChoice)
	}
	if got.APDU.ServiceChoiceName != "who-Is" {
		t.Errorf("ServiceChoiceName = %q", got.APDU.ServiceChoiceName)
	}
}

// TestDecode_IAmResponse pins an I-Am unconfirmed-request
// response — what each device sends in reply to Who-Is.
//
//	BVLC: 81 0B 00 18  (Original-Broadcast-NPDU, len 24)
//	NPDU: 01 20 FF FF 00 FF
//	APDU: 10 00 C4 02 00 00 7B 22 01 91 91 00 21 0F
//	      ^   ^   |---object id 123-|  |max apdu|  |seg=both|  |vendor 15|
//	      Unconfirmed-Request, i-Am
func TestDecode_IAmResponse(t *testing.T) {
	got, err := Decode("81 0B 00 18 01 20 FF FF 00 FF 10 00 C4 02 00 00 7B 22 01 91 91 00 21 0F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.APDU.PDUType != 1 {
		t.Errorf("PDUType = %d", got.APDU.PDUType)
	}
	if got.APDU.ServiceChoiceName != "i-Am" {
		t.Errorf("ServiceChoiceName = %q; want 'i-Am'", got.APDU.ServiceChoiceName)
	}
	if got.APDU.BodyHex == "" {
		t.Error("BodyHex empty; want object-id + max-APDU + segmentation + vendor")
	}
}

// TestDecode_ReadPropertyRequest pins a Confirmed-Request
// for readProperty. The byte after the header carries
// max-segments + max-APDU; invoke-id follows; then the
// service choice (12 = readProperty).
//
//	BVLC: 81 0A 00 11  (Original-Unicast-NPDU, len 17)
//	NPDU: 01 04         (v1, reply-expected)
//	APDU: 00 04 01 0C 0C 00 80 00 01 19 4D
//	      ^   ^   ^   ^
//	      |   |   |   service=readProperty
//	      |   |   invoke-id=1
//	      |   max-seg=0 (16), max-apdu=4 (1024)
//	      Confirmed-Request (PDU type 0)
func TestDecode_ReadPropertyRequest(t *testing.T) {
	got, err := Decode("81 0A 00 11 01 04 00 04 01 0C 0C 00 80 00 01 19 4D")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.BVLC.FunctionName != "Original-Unicast-NPDU" {
		t.Errorf("BVLC.FunctionName = %q", got.BVLC.FunctionName)
	}
	if !got.NPDU.ReplyExpected {
		t.Error("ReplyExpected = false; want true")
	}
	if got.APDU.PDUType != 0 {
		t.Errorf("PDUType = %d; want 0", got.APDU.PDUType)
	}
	if got.APDU.PDUTypeName != "Confirmed-Request-PDU" {
		t.Errorf("PDUTypeName = %q", got.APDU.PDUTypeName)
	}
	if got.APDU.InvokeID == nil || *got.APDU.InvokeID != 1 {
		t.Errorf("InvokeID = %v; want 1", got.APDU.InvokeID)
	}
	if got.APDU.ServiceChoice == nil || *got.APDU.ServiceChoice != 12 {
		t.Errorf("ServiceChoice = %v; want 12 (readProperty)", got.APDU.ServiceChoice)
	}
	if got.APDU.ServiceChoiceName != "readProperty" {
		t.Errorf("ServiceChoiceName = %q", got.APDU.ServiceChoiceName)
	}
	if got.APDU.MaxAPDULenAccepted == nil || *got.APDU.MaxAPDULenAccepted != 4 {
		t.Errorf("MaxAPDULenAccepted = %v; want 4", got.APDU.MaxAPDULenAccepted)
	}
}

// TestDecode_ComplexACK pins a ComplexACK response carrying
// the readProperty result.
//
//	BVLC: 81 0A 00 14  (Original-Unicast-NPDU, len 20)
//	NPDU: 01 00         (v1, no control flags)
//	APDU: 30 01 0C 0C 00 80 00 01 19 4D 3E 21 64 3F
//	      ^   ^   ^
//	      |   |   service=readProperty
//	      |   invoke-id=1
//	      ComplexACK (PDU type 3)
func TestDecode_ComplexACK(t *testing.T) {
	got, err := Decode("81 0A 00 14 01 00 30 01 0C 0C 00 80 00 01 19 4D 3E 21 64 3F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.APDU.PDUType != 3 {
		t.Errorf("PDUType = %d; want 3 (ComplexACK)", got.APDU.PDUType)
	}
	if got.APDU.ServiceChoiceName != "readProperty" {
		t.Errorf("ServiceChoiceName = %q", got.APDU.ServiceChoiceName)
	}
	if got.APDU.InvokeID == nil || *got.APDU.InvokeID != 1 {
		t.Errorf("InvokeID = %v; want 1", got.APDU.InvokeID)
	}
}

// TestDecode_ErrorPDU pins an Error response — an Error-PDU
// to a readProperty invocation.
func TestDecode_ErrorPDU(t *testing.T) {
	// 81 0A 00 0D 01 00 50 01 0C 91 02 91 1F
	// PDU type 5 = Error, invoke id 1, service 12 (readProperty),
	// then error_class (tag 91 02) + error_code (tag 91 1F)
	got, err := Decode("81 0A 00 0D 01 00 50 01 0C 91 02 91 1F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.APDU.PDUType != 5 {
		t.Errorf("PDUType = %d; want 5 (Error)", got.APDU.PDUType)
	}
	if got.APDU.ServiceChoiceName != "readProperty" {
		t.Errorf("ServiceChoiceName = %q", got.APDU.ServiceChoiceName)
	}
}

// TestDecode_RejectPDU pins a Reject response.
//
//	APDU: 60 02 09  (Reject, invoke=2, reason=9 unrecognized-service)
func TestDecode_RejectPDU(t *testing.T) {
	got, err := Decode("81 0A 00 09 01 00 60 02 09")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.APDU.PDUType != 6 {
		t.Errorf("PDUType = %d", got.APDU.PDUType)
	}
	if got.APDU.RejectReason == nil || *got.APDU.RejectReason != 9 {
		t.Errorf("RejectReason = %v; want 9", got.APDU.RejectReason)
	}
	if got.APDU.RejectReasonName != "unrecognized-service" {
		t.Errorf("RejectReasonName = %q", got.APDU.RejectReasonName)
	}
}

// TestDecode_AbortPDU pins an Abort response.
//
//	APDU: 70 01 0A  (Abort, invoke=1, reason=10 tsm-timeout)
func TestDecode_AbortPDU(t *testing.T) {
	got, err := Decode("81 0A 00 09 01 00 70 01 0A")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.APDU.PDUType != 7 {
		t.Errorf("PDUType = %d", got.APDU.PDUType)
	}
	if got.APDU.AbortReason == nil || *got.APDU.AbortReason != 10 {
		t.Errorf("AbortReason = %v; want 10", got.APDU.AbortReason)
	}
	if got.APDU.AbortReasonName != "tsm-timeout" {
		t.Errorf("AbortReasonName = %q", got.APDU.AbortReasonName)
	}
}

// TestDecode_SimpleACK pins a SimpleACK to a writeProperty
// confirmed request.
//
//	APDU: 20 0A 0F  (SimpleACK, invoke=10, service=15 writeProperty)
func TestDecode_SimpleACK(t *testing.T) {
	got, err := Decode("81 0A 00 09 01 00 20 0A 0F")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.APDU.PDUType != 2 {
		t.Errorf("PDUType = %d", got.APDU.PDUType)
	}
	if got.APDU.ServiceChoiceName != "writeProperty" {
		t.Errorf("ServiceChoiceName = %q", got.APDU.ServiceChoiceName)
	}
}

// TestDecode_NetworkLayerMessage exercises an NPDU carrying a
// network-layer management message (Who-Is-Router-To-Network).
//
//	BVLC: 81 0B 00 09  (Original-Broadcast-NPDU, len 9)
//	NPDU: 01 80 00     (v1, NLM bit, msg type = Who-Is-Router-To-Network)
//	Trailing: no APDU
func TestDecode_NetworkLayerMessage(t *testing.T) {
	// Adjust length: BVLC (4) + NPDU (3) = 7
	got, err := Decode("81 0B 00 07 01 80 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.NPDU.NetworkLayerMsg {
		t.Error("NetworkLayerMsg = false; want true")
	}
	if got.NPDU.MessageType == nil || *got.NPDU.MessageType != 0 {
		t.Errorf("MessageType = %v; want 0", got.NPDU.MessageType)
	}
	if got.NPDU.MessageTypeName != "Who-Is-Router-To-Network" {
		t.Errorf("MessageTypeName = %q", got.NPDU.MessageTypeName)
	}
	if got.APDU != nil {
		t.Error("APDU should be nil when NLM bit is set")
	}
}

// TestDecode_BVLCResult pins a BVLC-Result frame — the
// short BACnet/IP-only acknowledgement for foreign-device
// registration etc.
//
//	BVLC: 81 00 00 06  Result, length 6, then 2-byte result code 0000
func TestDecode_BVLCResult(t *testing.T) {
	got, err := Decode("81 00 00 06 00 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.BVLC.FunctionName != "BVLC-Result" {
		t.Errorf("BVLC.FunctionName = %q", got.BVLC.FunctionName)
	}
	// BVLC-Result doesn't carry an NPDU.
	if got.NPDU != nil {
		t.Error("NPDU should be nil for BVLC-Result")
	}
}

// TestDecode_BadType rejects non-BACnet/IP type byte.
func TestDecode_BadType(t *testing.T) {
	if _, err := Decode("82 0B 00 04"); err == nil {
		t.Error("BVLC type 0x82: want error (not BACnet/IP)")
	}
}

// TestDecode_BadLength rejects BVLC Length that doesn't match
// actual buffer.
func TestDecode_BadLength(t *testing.T) {
	// Declared length 100 but only 4 bytes provided
	if _, err := Decode("81 0B 00 64"); err == nil {
		t.Error("length mismatch: want error")
	}
}

// TestDecode_TooShort rejects frames shorter than the BVLC
// header.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("81 0B"); err == nil {
		t.Error("2-byte input: want error")
	}
}

// TestDecode_BadHex rejects garbage.
func TestDecode_BadHex(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty: want error")
	}
}

// TestDecode_Separators tolerates separators.
func TestDecode_Separators(t *testing.T) {
	got, err := Decode("81:0B-00_0C 01 20 FF FF 00 FF 10 08")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.APDU.ServiceChoiceName != "who-Is" {
		t.Errorf("ServiceChoiceName = %q", got.APDU.ServiceChoiceName)
	}
}

// TestBVLCFunctionNameTable spot-checks the table.
func TestBVLCFunctionNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "BVLC-Result",
		0x04: "Forwarded-NPDU",
		0x0A: "Original-Unicast-NPDU",
		0x0B: "Original-Broadcast-NPDU",
		0x0C: "Secure-BVLL",
	}
	for fn, want := range cases {
		if got := bvlcFunctionName(fn); got != want {
			t.Errorf("bvlcFunctionName(0x%02X) = %q; want %q", fn, got, want)
		}
	}
}

// TestConfirmedServiceTable spot-checks.
func TestConfirmedServiceTable(t *testing.T) {
	cases := map[int]string{
		5:  "subscribeCOV",
		12: "readProperty",
		14: "readPropertyMultiple",
		15: "writeProperty",
		16: "writePropertyMultiple",
		20: "reinitializeDevice",
	}
	for sc, want := range cases {
		if got := confirmedServiceName(sc); !strings.Contains(got, want) {
			t.Errorf("confirmedServiceName(%d) = %q; want substring %q", sc, got, want)
		}
	}
}

// TestUnconfirmedServiceTable spot-checks.
func TestUnconfirmedServiceTable(t *testing.T) {
	cases := map[int]string{
		0: "i-Am",
		1: "i-Have",
		6: "timeSynchronization",
		8: "who-Is",
	}
	for sc, want := range cases {
		if got := unconfirmedServiceName(sc); got != want {
			t.Errorf("unconfirmedServiceName(%d) = %q; want %q", sc, got, want)
		}
	}
}
