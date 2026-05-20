package ptpv2

import (
	"strings"
	"testing"
)

// TestDecodeSync pins a canonical PTPv2 Sync packet — one-step,
// domain 0, sequence 0x4321, with a 10-byte originTimestamp.
func TestDecodeSync(t *testing.T) {
	// transportSpecific=0, messageType=0 (Sync); ver=2;
	// messageLength=44; domain=0; reserved=0; flags=0x0200 (twoStep);
	// correction=0; reserved=0; sourcePortIdentity=
	// 00:11:22:FF:FE:33:44:55 / port 1; seq=0x4321; control=0;
	// logMessageInterval=-3 (= 0xFD); then 10-byte originTimestamp
	// = secs 0x000000000064 (100) + ns 0x0000F424 (62500).
	in := "00 02 002C 00 00 0200 0000000000000000 00000000 " +
		"00112233445566778899" +
		"AABB 00 FD" +
		"000000000064 0000F424"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageType != 0x0 || r.MessageTypeName != "Sync" {
		t.Errorf("messageType: got %d/%s want 0/Sync", r.MessageType, r.MessageTypeName)
	}
	if r.VersionPTP != 2 {
		t.Errorf("versionPTP: got %d want 2", r.VersionPTP)
	}
	if r.MessageLength != 44 {
		t.Errorf("messageLength: got %d want 44", r.MessageLength)
	}
	if r.SequenceID != 0xAABB {
		t.Errorf("sequenceId: got 0x%X want 0xAABB", r.SequenceID)
	}
	if r.LogMessageInterval != -3 {
		t.Errorf("logMessageInterval: got %d want -3", r.LogMessageInterval)
	}
	if !strings.Contains(r.FlagsDecoded, "twoStep") {
		t.Errorf("flags missing twoStep: %q", r.FlagsDecoded)
	}
	if r.OriginTimestamp == nil {
		t.Fatal("originTimestamp nil")
	}
	if r.OriginTimestamp.Seconds != 100 || r.OriginTimestamp.Nanoseconds != 62500 {
		t.Errorf("timestamp: got %d.%09d want 100.000062500",
			r.OriginTimestamp.Seconds, r.OriginTimestamp.Nanoseconds)
	}
}

// TestDecodeAnnounce pins the BMCA inputs from a canonical
// Announce packet.
func TestDecodeAnnounce(t *testing.T) {
	// header: messageType=0xB (Announce); ver=2; length=64;
	// domain=0; reserved=0; flags=0x0018 (ptpTimescale|timeTraceable);
	// correction=0; reserved=0; sourcePortIdentity, seq, control,
	// logMessageInterval=1 (= 1).
	header := "0B 02 0040 00 00 0018 0000000000000000 00000000 " +
		"00112233445566778899" +
		"00C8 00 01"
	// Announce body (30 bytes):
	//   originTimestamp = secs 0x000000000200 (512) + ns 0x00000000
	//   currentUtcOffset = 0x0025 (37)
	//   reserved = 00
	//   priority1 = 128 (0x80)
	//   clockQuality = clockClass 6 (0x06) + clockAccuracy 0x21
	//   (within 100 ns) + offsetScaledLogVariance 0x4E5D
	//   priority2 = 128 (0x80)
	//   grandmasterIdentity = AABBCCFFFEDDEEFF
	//   stepsRemoved = 0x0001
	//   timeSource = 0x20 (GPS)
	body := "000000000200 00000000 " +
		"0025 00 80 06 21 4E5D 80 AABBCCFFFEDDEEFF 0001 20"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Announce" {
		t.Errorf("type: got %q want Announce", r.MessageTypeName)
	}
	if !strings.Contains(r.FlagsDecoded, "ptpTimescale") ||
		!strings.Contains(r.FlagsDecoded, "timeTraceable") {
		t.Errorf("flags missing announce bits: %q", r.FlagsDecoded)
	}
	if r.AnnounceBody == nil {
		t.Fatal("announce body nil")
	}
	ab := r.AnnounceBody
	if ab.CurrentUtcOffsetSeconds != 37 {
		t.Errorf("utcOffset: got %d want 37", ab.CurrentUtcOffsetSeconds)
	}
	if ab.GrandmasterPriority1 != 128 || ab.GrandmasterPriority2 != 128 {
		t.Errorf("priorities: got %d/%d want 128/128",
			ab.GrandmasterPriority1, ab.GrandmasterPriority2)
	}
	if ab.GrandmasterClockClass != 6 {
		t.Errorf("clockClass: got %d want 6", ab.GrandmasterClockClass)
	}
	if ab.GrandmasterClockAccuracy != 0x21 {
		t.Errorf("clockAccuracy: got 0x%X want 0x21", ab.GrandmasterClockAccuracy)
	}
	if ab.GrandmasterClockAccuracyName != "within 100 ns" {
		t.Errorf("clockAccuracyName: got %q", ab.GrandmasterClockAccuracyName)
	}
	if ab.GrandmasterOffsetScaledLogVar != 0x4E5D {
		t.Errorf("offsetScaledLogVar: got 0x%X want 0x4E5D",
			ab.GrandmasterOffsetScaledLogVar)
	}
	if ab.GrandmasterIdentity != "AA:BB:CC:FF:FE:DD:EE:FF" {
		t.Errorf("grandmasterIdentity: got %q", ab.GrandmasterIdentity)
	}
	if ab.StepsRemoved != 1 {
		t.Errorf("stepsRemoved: got %d want 1", ab.StepsRemoved)
	}
	if ab.TimeSourceName != "GPS" {
		t.Errorf("timeSourceName: got %q want GPS", ab.TimeSourceName)
	}
}

// TestDecodeDelayResp pins the requestingPortIdentity copy-back
// that ties a Delay_Resp to the originating Delay_Req.
func TestDecodeDelayResp(t *testing.T) {
	// header: messageType=0x9 (Delay_Resp); ver=2; length=54;
	header := "09 02 0036 00 00 0000 0000000000000000 00000000 " +
		"DEADBEEFCAFEBABE0001" +
		"1234 00 7F"
	// body: receiveTimestamp + requestingPortIdentity (8-byte
	// clockIdentity + 2-byte portNumber).
	body := "000000000064 0000F424 " +
		"11223344FFFE5566 0005"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Delay_Resp" {
		t.Errorf("type: got %q want Delay_Resp", r.MessageTypeName)
	}
	if r.ReceiveTimestamp == nil {
		t.Fatal("receiveTimestamp nil")
	}
	if r.ReceiveTimestamp.Seconds != 100 || r.ReceiveTimestamp.Nanoseconds != 62500 {
		t.Errorf("receive ts: got %d.%09d",
			r.ReceiveTimestamp.Seconds, r.ReceiveTimestamp.Nanoseconds)
	}
	if r.RequestingPortIdentity == nil {
		t.Fatal("requestingPortIdentity nil")
	}
	if r.RequestingPortIdentity.PortNumber != 5 {
		t.Errorf("port: got %d want 5", r.RequestingPortIdentity.PortNumber)
	}
	if r.RequestingPortIdentity.ClockIdentity != "11:22:33:44:FF:FE:55:66" {
		t.Errorf("clockId: got %q", r.RequestingPortIdentity.ClockIdentity)
	}
}

// TestDecodePdelayResp pins a peer-delay response.
func TestDecodePdelayResp(t *testing.T) {
	header := "03 02 0036 00 00 0000 0000000000000000 00000000 " +
		"DEADBEEFCAFEBABE0001" +
		"5678 00 7F"
	body := "0000000000C8 00000064 " +
		"AABBCCDDFFFEEEFF000A"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Pdelay_Resp" {
		t.Errorf("type: got %q want Pdelay_Resp", r.MessageTypeName)
	}
	if r.RequestReceiptTimestamp == nil {
		t.Fatal("requestReceiptTimestamp nil")
	}
	if r.RequestReceiptTimestamp.Seconds != 200 {
		t.Errorf("seconds: got %d want 200", r.RequestReceiptTimestamp.Seconds)
	}
	if r.RequestingPortIdentity == nil ||
		r.RequestingPortIdentity.PortNumber != 10 {
		t.Errorf("requestingPortIdentity wrong")
	}
}

// TestMessageTypeNameTable smokes every catalogued type name.
func TestMessageTypeNameTable(t *testing.T) {
	want := map[int]string{
		0x0: "Sync", 0x1: "Delay_Req", 0x2: "Pdelay_Req",
		0x3: "Pdelay_Resp", 0x8: "Follow_Up", 0x9: "Delay_Resp",
		0xA: "Pdelay_Resp_Follow_Up", 0xB: "Announce",
		0xC: "Signaling", 0xD: "Management",
	}
	for k, v := range want {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(0x%X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(messageTypeName(0xF), "uncatalogued") {
		t.Errorf("messageTypeName(0xF) should mark uncatalogued")
	}
}

// TestTimeSourceNameTable smokes every catalogued time source.
func TestTimeSourceNameTable(t *testing.T) {
	want := map[int]string{
		0x10: "ATOMIC_CLOCK", 0x20: "GPS",
		0x30: "TERRESTRIAL_RADIO", 0x40: "PTP",
		0x50: "NTP", 0x60: "HAND_SET",
		0x90: "OTHER", 0xA0: "INTERNAL_OSCILLATOR",
	}
	for k, v := range want {
		if got := timeSourceName(k); got != v {
			t.Errorf("timeSourceName(0x%X) = %q want %q", k, got, v)
		}
	}
}

// TestClockAccuracyNameTable spot-checks the high-runner values.
func TestClockAccuracyNameTable(t *testing.T) {
	cases := map[int]string{
		0x20: "within 25 ns",
		0x23: "within 1 µs",
		0x2F: "within 1 s",
		0xFE: "UNKNOWN",
	}
	for k, v := range cases {
		if got := clockAccuracyName(k); got != v {
			t.Errorf("clockAccuracyName(0x%X) = %q want %q", k, got, v)
		}
	}
}

// TestDecodeFollowUp pins a Follow_Up — paired with two-step
// Sync messages to carry the precise origin timestamp after the
// fact.
func TestDecodeFollowUp(t *testing.T) {
	header := "08 02 002C 00 00 0000 0000000000000000 00000000 " +
		"DEADBEEFCAFEBABE0001" +
		"AABB 00 FD"
	body := "000000000064 0000F424"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "Follow_Up" {
		t.Errorf("type: got %q want Follow_Up", r.MessageTypeName)
	}
	if r.PreciseOriginTimestamp == nil {
		t.Fatal("preciseOriginTimestamp nil")
	}
	if r.PreciseOriginTimestamp.Seconds != 100 {
		t.Errorf("seconds: got %d want 100", r.PreciseOriginTimestamp.Seconds)
	}
}

// TestDecodeCorrectionField pins the scaled-nanoseconds 64-bit
// signed value transparent clocks accumulate.
func TestDecodeCorrectionField(t *testing.T) {
	// correction = 0x0000000001312D00 = 20,000,000 scaled-ns.
	header := "00 02 002C 00 00 0000 0000000001312D00 00000000 " +
		"DEADBEEFCAFEBABE0001" +
		"AABB 00 FD"
	body := "000000000064 0000F424"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.CorrectionField != 20000000 {
		t.Errorf("correctionField: got %d want 20000000", r.CorrectionField)
	}
}

// TestDecodeTLVSuffix asserts trailing TLV bytes are surfaced.
func TestDecodeTLVSuffix(t *testing.T) {
	header := "00 02 0030 00 00 0000 0000000000000000 00000000 " +
		"DEADBEEFCAFEBABE0001" +
		"AABB 00 FD"
	body := "000000000064 0000F424 DEADBEEF"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TLVSuffixHex != "DEADBEEF" {
		t.Errorf("tlv suffix: got %q want DEADBEEF", r.TLVSuffixHex)
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
	if _, err := Decode("00 02 002C 00 00 0000"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 33)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
