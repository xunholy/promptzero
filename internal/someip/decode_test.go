package someip

import (
	"strings"
	"testing"
)

func derefInt(p *int) int {
	if p == nil {
		return -1
	}
	return *p
}

// TestDecodeRequest pins a canonical SOME/IP REQUEST — method
// call on Service 0x1234, Method 0x0001 with a small payload.
func TestDecodeRequest(t *testing.T) {
	// header: serviceId=0x1234, methodId=0x0001, length=0x0000000A
	// (10 bytes = clientId + sessionId + version*2 + msgType +
	// retCode + 2 bytes payload), clientId=0x00AB, sessionId=0x0001,
	// protoVer=0x01, ifVer=0x02, msgType=0x00 (REQUEST),
	// retCode=0x00, payload=0xDEAD.
	in := "1234 0001 0000000A 00AB 0001 01 02 00 00 DEAD"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.ServiceID != 0x1234 || r.MethodID != 0x0001 {
		t.Errorf("serviceId/methodId: got 0x%X/0x%X", r.ServiceID, r.MethodID)
	}
	if r.IsEvent {
		t.Errorf("methodId 0x0001 should not be event")
	}
	if r.Length != 10 {
		t.Errorf("length: got %d want 10", r.Length)
	}
	if r.ClientID != 0x00AB || r.SessionID != 0x0001 {
		t.Errorf("client/session: got 0x%X/0x%X", r.ClientID, r.SessionID)
	}
	if r.ProtocolVersion != 1 || r.InterfaceVersion != 2 {
		t.Errorf("protoVer/ifVer: got %d/%d", r.ProtocolVersion, r.InterfaceVersion)
	}
	if r.MessageTypeName != "REQUEST" {
		t.Errorf("messageTypeName: got %q want REQUEST", r.MessageTypeName)
	}
	if r.ReturnCodeName != "E_OK" {
		t.Errorf("returnCodeName: got %q want E_OK", r.ReturnCodeName)
	}
	if r.PayloadHex != "DEAD" {
		t.Errorf("payload: got %q want DEAD", r.PayloadHex)
	}
}

// TestDecodeNotification pins a NOTIFICATION (event) — high bit of
// Method ID set means this is an event.
func TestDecodeNotification(t *testing.T) {
	// methodId 0x8001 has the event bit set.
	in := "1234 8001 00000008 0000 0001 01 02 02 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.IsEvent {
		t.Errorf("methodId 0x8001 must mark is_event")
	}
	if r.MessageTypeName != "NOTIFICATION" {
		t.Errorf("messageTypeName: got %q want NOTIFICATION", r.MessageTypeName)
	}
}

// TestDecodeErrorWithReturnCode pins an ERROR response with a
// catalogued return code.
func TestDecodeErrorWithReturnCode(t *testing.T) {
	// msgType=0x81 ERROR, returnCode=0x06 E_TIMEOUT.
	in := "1234 0001 00000008 00AB 0001 01 02 81 06"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MessageTypeName != "ERROR" {
		t.Errorf("messageTypeName: got %q want ERROR", r.MessageTypeName)
	}
	if r.ReturnCodeName != "E_TIMEOUT" {
		t.Errorf("returnCodeName: got %q want E_TIMEOUT", r.ReturnCodeName)
	}
}

// TestDecodeTPSegment pins TP-fragmentation segment detection.
func TestDecodeTPSegment(t *testing.T) {
	// msgType=0x20 (TP-bit set + base REQUEST 0x00).
	in := "1234 0001 00000008 00AB 0001 01 02 20 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.TPSegment {
		t.Errorf("TP-bit set but tp_segment=false")
	}
	if r.MessageTypeBase != 0x00 || r.MessageTypeName != "REQUEST" {
		t.Errorf("base/name: got 0x%X/%q want 0x00/REQUEST",
			r.MessageTypeBase, r.MessageTypeName)
	}
}

// TestDecodeSDOfferService pins a Service Discovery OFFER_SERVICE
// entry with an IPv4 endpoint option.
func TestDecodeSDOfferService(t *testing.T) {
	// Header: SD signature (0xFFFF 0x8100), NOTIFICATION.
	header := "FFFF 8100 0000003C 0000 0001 01 01 02 00"
	// SD body:
	//   flags 0xC0 (Reboot + Unicast), reserved 000000
	//   entriesLength=0x00000010 (16 bytes = one entry)
	//   entry: type=0x01 OFFER_SERVICE; idx1=00, idx2=00,
	//   numOpts=0x10 (1 first option, 0 second); service=0x1234
	//   instance=0x0001; majorVer=0x02; ttl=0x000003
	//   (3 seconds — not stop); minorVer=0x00000005.
	//   optionsLength=0x0000000C (12 bytes = one IPv4 endpoint
	//   option). Option: length=0x0009, type=0x04, reserved=0x00,
	//   IPv4 192.168.1.2, reserved 0x00, L4=0x11 (UDP), port=0x7530.
	body := "C0 000000 00000010 " +
		"01 00 00 10 1234 0001 02 000003 00000005 " +
		"0000000C " +
		"0009 04 00 C0A80102 00 11 7530"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.SDBody == nil {
		t.Fatal("sd_body nil")
	}
	if !r.SDBody.RebootFlag || !r.SDBody.UnicastFlag {
		t.Errorf("flags: reboot=%v unicast=%v want both true",
			r.SDBody.RebootFlag, r.SDBody.UnicastFlag)
	}
	if len(r.SDBody.Entries) != 1 {
		t.Fatalf("entries: got %d want 1", len(r.SDBody.Entries))
	}
	e := r.SDBody.Entries[0]
	if e.TypeName != "OFFER_SERVICE" {
		t.Errorf("entry typeName: got %q want OFFER_SERVICE", e.TypeName)
	}
	if e.ServiceID != 0x1234 || e.InstanceID != 0x0001 {
		t.Errorf("entry service/instance: got 0x%X/0x%X",
			e.ServiceID, e.InstanceID)
	}
	if e.TTL != 3 {
		t.Errorf("entry TTL: got %d want 3", e.TTL)
	}
	if e.MinorVersion == nil || *e.MinorVersion != 5 {
		t.Errorf("minorVersion: got %v want 5", e.MinorVersion)
	}
	if len(r.SDBody.Options) != 1 {
		t.Fatalf("options: got %d want 1", len(r.SDBody.Options))
	}
	o := r.SDBody.Options[0]
	if o.TypeName != "IPv4 Endpoint" {
		t.Errorf("option typeName: got %q want IPv4 Endpoint", o.TypeName)
	}
	if o.IPAddress != "192.168.1.2" {
		t.Errorf("option ip: got %q want 192.168.1.2", o.IPAddress)
	}
	if o.L4Protocol != "UDP" || o.Port != 30000 {
		t.Errorf("option l4/port: got %s/%d want UDP/30000",
			o.L4Protocol, o.Port)
	}
}

// TestDecodeSDStopOfferService pins a STOP_OFFER_SERVICE entry —
// same type byte 0x01 but TTL = 0.
func TestDecodeSDStopOfferService(t *testing.T) {
	header := "FFFF 8100 00000020 0000 0002 01 01 02 00"
	// TTL = 0x000000 → STOP_OFFER_SERVICE.
	body := "00 000000 00000010 " +
		"01 00 00 10 1234 0001 02 000000 00000005 " +
		"00000000"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.SDBody == nil || len(r.SDBody.Entries) != 1 {
		t.Fatalf("sd_body or entries missing")
	}
	e := r.SDBody.Entries[0]
	if e.TypeName != "STOP_OFFER_SERVICE" {
		t.Errorf("typeName: got %q want STOP_OFFER_SERVICE", e.TypeName)
	}
	if !e.IsStop {
		t.Errorf("is_stop should be true when TTL == 0")
	}
}

// TestDecodeSDSubscribe pins a SUBSCRIBE_EVENTGROUP entry —
// surfaces Counter + EventgroupID instead of MinorVersion.
func TestDecodeSDSubscribe(t *testing.T) {
	header := "FFFF 8100 00000020 0000 0003 01 01 02 00"
	// type=0x06; entry trailing 4 bytes (entry bytes 12-15):
	// byte 12 Reserved; byte 13 = 0x07 (Initial-Data-Requested
	// bit clear, Counter = 0x07 in low nibble); bytes 14-15 =
	// 0x0123 Eventgroup ID.
	body := "00 000000 00000010 " +
		"06 00 00 10 1234 0001 02 000003 00 07 0123 " +
		"00000000"
	r, err := Decode(header + body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.SDBody == nil || len(r.SDBody.Entries) != 1 {
		t.Fatalf("sd_body or entries missing")
	}
	e := r.SDBody.Entries[0]
	if e.TypeName != "SUBSCRIBE_EVENTGROUP" {
		t.Errorf("typeName: got %q want SUBSCRIBE_EVENTGROUP", e.TypeName)
	}
	if e.Counter == nil || *e.Counter != 7 {
		t.Errorf("counter: got %v want 7", derefInt(e.Counter))
	}
	if e.EventgroupID == nil || *e.EventgroupID != 0x0123 {
		t.Errorf("eventgroupId: got 0x%X want 0x123",
			derefInt(e.EventgroupID))
	}
}

// TestMessageTypeNameTable smokes every catalogued base type.
func TestMessageTypeNameTable(t *testing.T) {
	want := map[int]string{
		0x00: "REQUEST", 0x01: "REQUEST_NO_RETURN", 0x02: "NOTIFICATION",
		0x40: "REQUEST_ACK", 0x41: "REQUEST_NO_RETURN_ACK",
		0x42: "NOTIFICATION_ACK", 0x80: "RESPONSE", 0x81: "ERROR",
	}
	for k, v := range want {
		if got := messageTypeName(k); got != v {
			t.Errorf("messageTypeName(0x%02X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(messageTypeName(0xFE), "uncatalogued") {
		t.Errorf("messageTypeName(0xFE) should mark uncatalogued")
	}
}

// TestReturnCodeNameTable smokes every catalogued return code.
func TestReturnCodeNameTable(t *testing.T) {
	want := map[int]string{
		0x00: "E_OK", 0x01: "E_NOT_OK",
		0x02: "E_UNKNOWN_SERVICE", 0x03: "E_UNKNOWN_METHOD",
		0x04: "E_NOT_READY", 0x05: "E_NOT_REACHABLE",
		0x06: "E_TIMEOUT", 0x07: "E_WRONG_PROTOCOL_VERSION",
		0x08: "E_WRONG_INTERFACE_VERSION", 0x09: "E_MALFORMED_MESSAGE",
		0x0A: "E_WRONG_MESSAGE_TYPE", 0x0B: "E_E2E_REPEATED",
	}
	for k, v := range want {
		if got := returnCodeName(k); got != v {
			t.Errorf("returnCodeName(0x%02X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(returnCodeName(0x30), "application-specific") {
		t.Errorf("returnCode 0x30 should mark application-specific")
	}
	if !strings.HasPrefix(returnCodeName(0x10), "reserved") {
		t.Errorf("returnCode 0x10 should mark reserved")
	}
}

func TestDecodeRejectsEmpty(t *testing.T) {
	if _, err := Decode(""); err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecodeRejectsOdd(t *testing.T) {
	if _, err := Decode("ABC"); err == nil {
		t.Fatal("want error for odd-length input")
	}
}

func TestDecodeRejectsShortHeader(t *testing.T) {
	if _, err := Decode("1234 0001 0000000A"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ" + strings.Repeat("00", 15)); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
