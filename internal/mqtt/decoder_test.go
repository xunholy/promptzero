package mqtt

import (
	"strings"
	"testing"
)

// TestDecode_CONNECT pins a minimal MQTT v3.1.1 CONNECT
// packet. The client connects with:
//   - Protocol name "MQTT", version 4
//   - Clean session, no will, no auth
//   - Keep alive 60s
//   - Client ID "testClient"
//
// Fixed header: 0x10 (CONNECT, flags=0)
// Remaining length: 22 bytes
// Variable header:
//
//	00 04 4D 51 54 54  (proto name "MQTT", 2-byte len)
//	04                 (proto version 4)
//	02                 (connect flags: clean session bit 1)
//	00 3C              (keep alive 60)
//
// Payload:
//
//	00 0A 74 65 73 74 43 6C 69 65 6E 74 ("testClient", 2-byte len + 10 bytes)
//
// Total = 22 bytes body + 2 byte fixed header = 24 bytes
func TestDecode_CONNECT(t *testing.T) {
	hex := "10 16 " + // Fixed header: CONNECT, remaining length 22
		"00 04 4D 51 54 54 " + // protocol name "MQTT"
		"04 " + // protocol version 4
		"02 " + // connect flags: clean session
		"00 3C " + // keep alive 60
		"00 0A 74 65 73 74 43 6C 69 65 6E 74" // client ID "testClient"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.PacketTypeName != "CONNECT" {
		t.Errorf("PacketTypeName = %q", got.FixedHeader.PacketTypeName)
	}
	if got.ProtocolName != "MQTT" {
		t.Errorf("ProtocolName = %q", got.ProtocolName)
	}
	if got.ProtocolVersion != 4 {
		t.Errorf("ProtocolVersion = %d", got.ProtocolVersion)
	}
	if !got.CleanSession {
		t.Error("CleanSession should be true")
	}
	if got.KeepAlive != 60 {
		t.Errorf("KeepAlive = %d", got.KeepAlive)
	}
	if got.ClientID != "testClient" {
		t.Errorf("ClientID = %q", got.ClientID)
	}
}

// TestDecode_CONNECT_WithAuth pins a CONNECT with username +
// password set.
func TestDecode_CONNECT_WithAuth(t *testing.T) {
	// Connect flags: username (0x80) + password (0x40) + clean (0x02) = 0xC2
	// Payload: client ID + username + password
	hex := "10 21 " + // Remaining length 33 (counted: 6+1+1+2+6+7+10)
		"00 04 4D 51 54 54 " + // proto name "MQTT"
		"04 " + // version 4
		"C2 " + // flags: username + password + clean
		"00 1E " + // keep alive 30
		"00 04 75 73 65 72 " + // client ID "user"
		"00 05 41 6C 69 63 65 " + // username "Alice"
		"00 08 73 65 63 72 65 74 31 32" // password "secret12"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !got.UsernameFlag || !got.PasswordFlag {
		t.Errorf("UsernameFlag=%v PasswordFlag=%v; want both true",
			got.UsernameFlag, got.PasswordFlag)
	}
	if got.Username != "Alice" {
		t.Errorf("Username = %q", got.Username)
	}
	if got.Password != "secret12" {
		t.Errorf("Password = %q", got.Password)
	}
}

// TestDecode_CONNACK pins a CONNACK packet: session present
// false, return code 0 (accepted).
func TestDecode_CONNACK(t *testing.T) {
	// Fixed header: 0x20 (CONNACK)
	// Remaining length: 2
	// Body: 00 00 (session_present=0, return_code=0)
	got, err := Decode("20 02 00 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.PacketTypeName != "CONNACK" {
		t.Errorf("PacketTypeName = %q", got.FixedHeader.PacketTypeName)
	}
	if got.SessionPresent {
		t.Error("SessionPresent should be false")
	}
	if got.ReturnCode != 0 {
		t.Errorf("ReturnCode = %d", got.ReturnCode)
	}
	if got.ReturnCodeName != "Connection Accepted" {
		t.Errorf("ReturnCodeName = %q", got.ReturnCodeName)
	}
}

// TestDecode_CONNACK_RefusedBadCreds pins CONNACK return code 4
// (bad username/password).
func TestDecode_CONNACK_RefusedBadCreds(t *testing.T) {
	got, err := Decode("20 02 00 04")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.ReturnCode != 4 {
		t.Errorf("ReturnCode = %d; want 4", got.ReturnCode)
	}
	if !strings.Contains(got.ReturnCodeName, "bad username or password") {
		t.Errorf("ReturnCodeName = %q", got.ReturnCodeName)
	}
}

// TestDecode_PUBLISH pins a PUBLISH packet with QoS 0:
//
//	Topic "sensors/temperature"
//	Payload "23.5"
//	QoS 0 (no packet ID)
func TestDecode_PUBLISH(t *testing.T) {
	// Topic "sensors/temperature" = 19 bytes
	// Payload "23.5" = 4 bytes
	// Body = 2 (topic len) + 19 (topic) + 4 (payload) = 25
	hex := "30 19 " + // Fixed header: PUBLISH (3<<4=0x30), flags=0 (QoS=0), rem len 25
		"00 13 " + // topic length 19
		"73 65 6E 73 6F 72 73 2F 74 65 6D 70 65 72 61 74 75 72 65 " + // "sensors/temperature"
		"32 33 2E 35" // "23.5"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.PacketTypeName != "PUBLISH" {
		t.Errorf("PacketTypeName = %q", got.FixedHeader.PacketTypeName)
	}
	if got.PublishFlags == nil {
		t.Fatal("PublishFlags nil")
	}
	if got.PublishFlags.QoS != 0 {
		t.Errorf("QoS = %d", got.PublishFlags.QoS)
	}
	if got.TopicName != "sensors/temperature" {
		t.Errorf("TopicName = %q", got.TopicName)
	}
	if got.PayloadString != "23.5" {
		t.Errorf("PayloadString = %q", got.PayloadString)
	}
}

// TestDecode_PUBLISH_QoS1WithRetain — QoS=1, RETAIN=1.
// Fixed header byte 0 = (3<<4) | flags. flags = QoS<<1 | RETAIN
// = 0x02 | 0x01 = 0x03. So byte 0 = 0x33.
func TestDecode_PUBLISH_QoS1WithRetain(t *testing.T) {
	// Topic "a" (1 byte), packet ID 0x0001, payload "x"
	// Body = 2+1 (topic) + 2 (pkt id) + 1 (payload) = 6
	hex := "33 06 " +
		"00 01 61 " + // topic "a"
		"00 01 " + // packet ID 1
		"78" // payload "x"
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PublishFlags.QoS != 1 {
		t.Errorf("QoS = %d; want 1", got.PublishFlags.QoS)
	}
	if !got.PublishFlags.Retain {
		t.Error("Retain should be true")
	}
	if got.PacketID != 1 {
		t.Errorf("PacketID = %d", got.PacketID)
	}
}

// TestDecode_SUBSCRIBE pins a SUBSCRIBE with 2 topic filters.
func TestDecode_SUBSCRIBE(t *testing.T) {
	// Fixed header: 0x82 (SUBSCRIBE = 8, flags = 0x02 per spec)
	// Body: packet ID 0x0042 + topic filter "a/+" QoS 1 + filter
	// "b/#" QoS 0
	// Topic "a/+" (3 bytes) + QoS byte = 6 bytes
	// Topic "b/#" (3 bytes) + QoS byte = 6 bytes
	// Total body = 2 + 6 + 6 = 14
	hex := "82 0E " +
		"00 42 " + // packet ID
		"00 03 61 2F 2B 01 " + // topic "a/+", QoS 1
		"00 03 62 2F 23 00" // topic "b/#", QoS 0
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.PacketTypeName != "SUBSCRIBE" {
		t.Errorf("PacketTypeName = %q", got.FixedHeader.PacketTypeName)
	}
	if got.PacketID != 0x0042 {
		t.Errorf("PacketID = 0x%X", got.PacketID)
	}
	if len(got.TopicFilters) != 2 {
		t.Fatalf("TopicFilters count = %d", len(got.TopicFilters))
	}
	if got.TopicFilters[0].Filter != "a/+" || got.TopicFilters[0].QoS != 1 {
		t.Errorf("Filter[0] = %+v", got.TopicFilters[0])
	}
	if got.TopicFilters[1].Filter != "b/#" || got.TopicFilters[1].QoS != 0 {
		t.Errorf("Filter[1] = %+v", got.TopicFilters[1])
	}
}

// TestDecode_SUBACK pins a SUBACK with 2 return codes.
func TestDecode_SUBACK(t *testing.T) {
	// Fixed header: 0x90 (SUBACK), body = packet ID + 2 return codes
	hex := "90 04 00 42 01 00" // pkt ID 0x42, codes 0x01 (QoS 1 granted) + 0x00
	got, err := Decode(hex)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.PacketID != 0x42 {
		t.Errorf("PacketID = 0x%X", got.PacketID)
	}
	if len(got.SubReturnCodes) != 2 {
		t.Errorf("SubReturnCodes count = %d", len(got.SubReturnCodes))
	}
	if got.SubReturnCodes[0] != 1 || got.SubReturnCodes[1] != 0 {
		t.Errorf("SubReturnCodes = %v", got.SubReturnCodes)
	}
}

// TestDecode_PUBACK pins a PUBACK (header + packet ID).
func TestDecode_PUBACK(t *testing.T) {
	// 0x40 (PUBACK), remaining length 2, packet ID 0x0001
	got, err := Decode("40 02 00 01")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.PacketTypeName != "PUBACK" {
		t.Errorf("PacketTypeName = %q", got.FixedHeader.PacketTypeName)
	}
	if got.PacketID != 1 {
		t.Errorf("PacketID = %d", got.PacketID)
	}
}

// TestDecode_PINGREQ — header-only packet.
func TestDecode_PINGREQ(t *testing.T) {
	got, err := Decode("C0 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.PacketTypeName != "PINGREQ" {
		t.Errorf("PacketTypeName = %q", got.FixedHeader.PacketTypeName)
	}
	if got.FixedHeader.RemainingLength != 0 {
		t.Errorf("RemainingLength = %d", got.FixedHeader.RemainingLength)
	}
}

// TestDecode_DISCONNECT — header-only.
func TestDecode_DISCONNECT(t *testing.T) {
	got, err := Decode("E0 00")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.PacketTypeName != "DISCONNECT" {
		t.Errorf("PacketTypeName = %q", got.FixedHeader.PacketTypeName)
	}
}

// TestDecode_VariableLengthEncoding exercises the variable-byte-
// integer remaining length with values > 127 (multi-byte).
func TestDecode_VariableLengthEncoding(t *testing.T) {
	// Construct a PUBLISH with payload that pushes remaining
	// length to 200 (2-byte var-len: 0xC8 0x01 = 200).
	// Var-len 200 = 0x80 set on first byte (0xC8) signals
	// continuation, next byte 0x01 contributes 128. 0xC8 & 0x7F
	// = 72. 72 + 1*128 = 200. ✓
	topic := "x"
	payloadLen := 200 - 2 - 1 // 2 topic-len + 1 topic = 3; payload = 197
	pkt := []byte{0x30, 0xC8, 0x01, 0x00, 0x01, 'x'}
	for i := 0; i < payloadLen; i++ {
		pkt = append(pkt, 'A')
	}
	got, err := DecodeBytes(pkt)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got.FixedHeader.RemainingLength != 200 {
		t.Errorf("RemainingLength = %d; want 200", got.FixedHeader.RemainingLength)
	}
	if got.TopicName != topic {
		t.Errorf("TopicName = %q", got.TopicName)
	}
	if len(got.PayloadHex) != payloadLen*2 {
		t.Errorf("PayloadHex length = %d; want %d", len(got.PayloadHex), payloadLen*2)
	}
}

// TestDecode_TruncatedRemainingLength — declared length exceeds
// buffer.
func TestDecode_TruncatedRemainingLength(t *testing.T) {
	// PUBLISH with remaining length 100, but no body.
	_, err := Decode("30 64")
	if err == nil {
		t.Fatal("want error for truncated body")
	}
}

// TestDecode_TooShort — packet shorter than 2-byte fixed header.
func TestDecode_TooShort(t *testing.T) {
	if _, err := Decode("30"); err == nil {
		t.Error("1-byte input: want error")
	}
	if _, err := Decode(""); err == nil {
		t.Error("empty input: want error")
	}
}

// TestDecode_BadInput — invalid hex.
func TestDecode_BadInput(t *testing.T) {
	if _, err := Decode("ZZ"); err == nil {
		t.Error("invalid hex: want error")
	}
}

// TestDecode_Separators — ':' / '-' / '_' / whitespace.
func TestDecode_Separators(t *testing.T) {
	base := "20 02 00 00"
	for _, sep := range []string{":", "-", "_", " "} {
		in := strings.ReplaceAll(base, " ", sep)
		got, err := Decode(in)
		if err != nil {
			t.Errorf("sep=%q: %v", sep, err)
			continue
		}
		if got.FixedHeader.PacketTypeName != "CONNACK" {
			t.Errorf("sep=%q: PacketTypeName = %q", sep, got.FixedHeader.PacketTypeName)
		}
	}
}

// TestPacketTypeNames spot-checks the packet-type name table.
func TestPacketTypeNames(t *testing.T) {
	cases := map[PacketType]string{
		PacketTypeCONNECT:    "CONNECT",
		PacketTypeCONNACK:    "CONNACK",
		PacketTypePUBLISH:    "PUBLISH",
		PacketTypeSUBSCRIBE:  "SUBSCRIBE",
		PacketTypeDISCONNECT: "DISCONNECT",
	}
	for pt, want := range cases {
		if got := pt.String(); got != want {
			t.Errorf("PacketType(%d).String() = %q; want %q", pt, got, want)
		}
	}
}
