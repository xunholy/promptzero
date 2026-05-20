package mqttsn

import (
	"strings"
	"testing"
)

// TestDecodeConnect pins a canonical CONNECT message — opens
// the sensor's session with a ClientId.
func TestDecodeConnect(t *testing.T) {
	// Length = 13 (header 2 + flags 1 + protoID 1 + duration 2
	// + clientId "sensor01" = 8 → total 14? Let me recount.
	// Actually: length includes itself, so 1 (len) + 1 (type)
	// + 1 (flags) + 1 (protoID) + 2 (duration) + 8 (clientId)
	// = 14. Length = 14 = 0x0E.
	// Flags = 0x04 (CleanSession + QoS 0 + Topic Type 0).
	// ProtocolId = 0x01. Duration = 60 (0x003C). ClientId =
	// "sensor01" (8 bytes ASCII).
	in := "0E 04 04 01 003C 73 65 6E 73 6F 72 30 31"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MsgTypeName != "CONNECT" {
		t.Errorf("msgType: got %q want CONNECT", r.MsgTypeName)
	}
	if r.Length != 14 {
		t.Errorf("length: got %d want 14", r.Length)
	}
	if !r.CleanSession {
		t.Errorf("CleanSession should be true")
	}
	if r.ProtocolID != 1 {
		t.Errorf("protocolID: got %d want 1", r.ProtocolID)
	}
	if r.Duration != 60 {
		t.Errorf("duration: got %d want 60", r.Duration)
	}
	if r.ClientID != "sensor01" {
		t.Errorf("clientID: got %q want sensor01", r.ClientID)
	}
}

// TestDecodeConnack pins server CONNACK accepting the session.
func TestDecodeConnack(t *testing.T) {
	in := "03 05 00"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MsgTypeName != "CONNACK" {
		t.Errorf("msgType: got %q want CONNACK", r.MsgTypeName)
	}
	if r.ReturnCodeName != "Accepted" {
		t.Errorf("returnCode: got %q want Accepted", r.ReturnCodeName)
	}
}

// TestDecodeRegister pins a topic-registration round-trip.
func TestDecodeRegister(t *testing.T) {
	// REGISTER: TopicId = 0x0001, MsgId = 0x0002, TopicName
	// "temp/celsius" (12 bytes).
	// Length = 1+1+2+2+12 = 18 = 0x12.
	in := "12 0A 0001 0002 74 65 6D 70 2F 63 65 6C 73 69 75 73"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MsgTypeName != "REGISTER" {
		t.Errorf("msgType: got %q want REGISTER", r.MsgTypeName)
	}
	if r.TopicID != 1 {
		t.Errorf("topicID: got %d want 1", r.TopicID)
	}
	if r.MsgID != 2 {
		t.Errorf("msgID: got %d want 2", r.MsgID)
	}
	if r.TopicName != "temp/celsius" {
		t.Errorf("topicName: got %q want temp/celsius", r.TopicName)
	}
}

// TestDecodePublish pins a sensor PUBLISH with binary payload.
func TestDecodePublish(t *testing.T) {
	// PUBLISH: Flags = 0x20 (QoS 1 + Topic Type 0); TopicId
	// 0x0001; MsgId 0x0010; Data 0xCAFEBABE.
	// Length = 1+1+1+2+2+4 = 11 = 0x0B.
	in := "0B 0C 20 0001 0010 CAFEBABE"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MsgTypeName != "PUBLISH" {
		t.Errorf("msgType: got %q want PUBLISH", r.MsgTypeName)
	}
	if r.QoS != 1 {
		t.Errorf("qos: got %d want 1", r.QoS)
	}
	if r.TopicID != 1 {
		t.Errorf("topicID: got %d want 1", r.TopicID)
	}
	if r.MsgID != 0x10 {
		t.Errorf("msgID: got 0x%X want 0x10", r.MsgID)
	}
	if r.DataHex != "CAFEBABE" {
		t.Errorf("data: got %q want CAFEBABE", r.DataHex)
	}
}

// TestDecodePublishQoSMinus1 pins the MQTT-SN-specific QoS = -1
// (fire-and-forget) decode — Flags QoS field = 0b11.
func TestDecodePublishQoSMinus1(t *testing.T) {
	// Flags = 0x60 (QoS 11 → -1).
	in := "0B 0C 60 0001 0000 DEADBEEF"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.QoS != -1 {
		t.Errorf("qos: got %d want -1 (fire-and-forget)", r.QoS)
	}
}

// TestDecodeSubscribeByName pins SUBSCRIBE with TopicIdType=0
// (normal topic name).
func TestDecodeSubscribeByName(t *testing.T) {
	// Flags = 0x00 (QoS 0, TopicIdType normal); MsgId 0x0003;
	// TopicName "+/data".
	// Length = 1+1+1+2+6 = 11 = 0x0B.
	in := "0B 12 00 0003 2B 2F 64 61 74 61"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MsgTypeName != "SUBSCRIBE" {
		t.Errorf("msgType: got %q want SUBSCRIBE", r.MsgTypeName)
	}
	if r.TopicIDTypeName != "normal" {
		t.Errorf("topicIdType: got %q want normal", r.TopicIDTypeName)
	}
	if r.TopicName != "+/data" {
		t.Errorf("topicName: got %q want +/data", r.TopicName)
	}
}

// TestDecodeSubscribeByID pins SUBSCRIBE with TopicIdType=1
// (predefined TopicId).
func TestDecodeSubscribeByID(t *testing.T) {
	// Flags = 0x01 (predefined TopicId); MsgId 0x0004; TopicId
	// 0x00AA.
	in := "07 12 01 0004 00AA"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.TopicIDTypeName != "predefined" {
		t.Errorf("topicIdType: got %q want predefined", r.TopicIDTypeName)
	}
	if r.TopicID != 0xAA {
		t.Errorf("topicID: got 0x%X want 0xAA", r.TopicID)
	}
}

// TestDecodeDisconnectWithDuration pins a sleep-mode DISCONNECT
// — client tells the gateway "buffer messages for 300 seconds
// while I doze".
func TestDecodeDisconnectWithDuration(t *testing.T) {
	in := "04 18 012C"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MsgTypeName != "DISCONNECT" {
		t.Errorf("msgType: got %q want DISCONNECT", r.MsgTypeName)
	}
	if r.Duration != 300 {
		t.Errorf("duration: got %d want 300", r.Duration)
	}
}

// TestDecodeAdvertise pins a gateway ADVERTISE broadcast.
func TestDecodeAdvertise(t *testing.T) {
	// GwId = 0x05; Duration = 30s.
	in := "05 00 05 001E"
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r.MsgTypeName != "ADVERTISE" {
		t.Errorf("msgType: got %q want ADVERTISE", r.MsgTypeName)
	}
	if r.GwID != 5 {
		t.Errorf("gwID: got %d want 5", r.GwID)
	}
	if r.Duration != 30 {
		t.Errorf("duration: got %d want 30", r.Duration)
	}
}

// TestDecodeLongFormat pins long-form (length ≥ 256) message
// header decode.
func TestDecodeLongFormat(t *testing.T) {
	// 0x01 + length 0x0100 (256) + MsgType 0x0C (PUBLISH) +
	// Flags 0x00 + TopicId 0x0001 + MsgId 0x0002 + 247 bytes
	// of "A".
	dataHex := strings.Repeat("41", 247)
	in := "01 0100 0C 00 0001 0002 " + dataHex
	r, err := Decode(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !r.LongFormat {
		t.Errorf("expected long format")
	}
	if r.Length != 256 {
		t.Errorf("length: got %d want 256", r.Length)
	}
	if r.MsgTypeName != "PUBLISH" {
		t.Errorf("msgType: got %q want PUBLISH", r.MsgTypeName)
	}
	if len(r.DataHex) != 247*2 {
		t.Errorf("data length: got %d hex chars want %d", len(r.DataHex), 247*2)
	}
}

// TestMsgTypeNameTable spot-checks key catalogued types.
func TestMsgTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "ADVERTISE", 0x01: "SEARCHGW", 0x02: "GWINFO",
		0x04: "CONNECT", 0x05: "CONNACK", 0x0A: "REGISTER",
		0x0C: "PUBLISH", 0x12: "SUBSCRIBE", 0x16: "PINGREQ",
		0x18: "DISCONNECT",
	}
	for k, v := range cases {
		if got := msgTypeName(k); got != v {
			t.Errorf("msgTypeName(0x%02X) = %q want %q", k, got, v)
		}
	}
	if !strings.HasPrefix(msgTypeName(0xEE), "uncatalogued") {
		t.Errorf("uncatalogued msgType should be flagged")
	}
}

// TestReturnCodeNameTable covers every catalogued return code.
func TestReturnCodeNameTable(t *testing.T) {
	cases := map[int]string{
		0x00: "Accepted",
		0x01: "Rejected_congestion",
		0x02: "Rejected_invalid_topic_ID",
		0x03: "Rejected_not_supported",
	}
	for k, v := range cases {
		if got := returnCodeName(k); got != v {
			t.Errorf("returnCodeName(0x%02X) = %q want %q", k, got, v)
		}
	}
}

// TestTopicIDTypeNameTable covers every catalogued topic-id type.
func TestTopicIDTypeNameTable(t *testing.T) {
	cases := map[int]string{
		0: "normal", 1: "predefined", 2: "short_name", 3: "reserved",
	}
	for k, v := range cases {
		if got := topicIDTypeName(k); got != v {
			t.Errorf("topicIDTypeName(%d) = %q want %q", k, got, v)
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
	if _, err := Decode("0E"); err == nil {
		t.Fatal("want error for short header")
	}
}

func TestDecodeRejectsLongFormShort(t *testing.T) {
	if _, err := Decode("01 01"); err == nil {
		t.Fatal("want error for short long-form header")
	}
}

func TestDecodeRejectsBadHex(t *testing.T) {
	if _, err := Decode("ZZ 0C"); err == nil {
		t.Fatal("want error for non-hex chars")
	}
}
