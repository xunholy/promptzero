package rtmp

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// rtmpHandshake builds a C0+C1 or S0+S1 block: 1-byte version +
// 4-byte timestamp + 4 zero bytes + 1528 bytes of random data.
func rtmpHandshake(version byte) []byte {
	b := make([]byte, handshakeSize)
	b[0] = version
	// timestamp bytes 1-4: leave zero (valid)
	// zero bytes 5-8: already zero
	// random data bytes 9-1536: already zero
	return b
}

// rtmpChunkFmt0 builds a minimal RTMP chunk with fmt=0 header.
// cs_id must be 2-63 (direct form). payload is the message body.
func rtmpChunkFmt0(csID byte, timestamp uint32, msgType byte, streamID uint32, payload []byte) []byte {
	msgLen := len(payload)
	// basic header (1 byte): fmt=0 (bits 7-6 = 00) | cs_id
	var b []byte
	b = append(b, csID&0x3F)
	// timestamp (3 BE)
	b = append(b, byte(timestamp>>16), byte(timestamp>>8), byte(timestamp))
	// message length (3 BE)
	b = append(b, byte(msgLen>>16), byte(msgLen>>8), byte(msgLen))
	// message type id
	b = append(b, msgType)
	// stream id (4 LE)
	sid := make([]byte, 4)
	binary.LittleEndian.PutUint32(sid, streamID)
	b = append(b, sid...)
	// payload
	b = append(b, payload...)
	return b
}

// amf0String encodes an AMF0 string: marker 0x02 + 2-byte BE length + data.
func amf0String(s string) []byte {
	b := []byte{0x02}
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(s)))
	b = append(b, lb...)
	b = append(b, []byte(s)...)
	return b
}

// amf0ShortString encodes a bare AMF0 object-key string (no 0x02 marker):
// 2-byte BE length + data.
func amf0ShortString(s string) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	b = append(b, []byte(s)...)
	return b
}

// buildConnectPayload builds an AMF0 Command Message payload for a
// "connect" command containing an AMF0 object with "app" and "tcUrl".
func buildConnectPayload(app, tcURL, flashVer string) []byte {
	var payload []byte
	payload = append(payload, amf0String("connect")...)
	// transaction ID: AMF0 number 0x00 + 8-byte float64 (1.0)
	payload = append(payload, 0x00,
		0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) // 1.0 as IEEE 754 double BE
	// AMF0 Object marker 0x03
	payload = append(payload, 0x03)
	// property: "app"
	payload = append(payload, amf0ShortString("app")...)
	payload = append(payload, amf0String(app)...)
	// property: "tcUrl"
	payload = append(payload, amf0ShortString("tcUrl")...)
	payload = append(payload, amf0String(tcURL)...)
	// property: "flashVer"
	payload = append(payload, amf0ShortString("flashVer")...)
	payload = append(payload, amf0String(flashVer)...)
	// Object End marker 0x00 0x00 0x09
	payload = append(payload, 0x00, 0x00, 0x09)
	return payload
}

func TestDecode_HandshakeC0C1_Plaintext(t *testing.T) {
	b := rtmpHandshake(0x03)
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsHandshake {
		t.Error("expected is_handshake=true")
	}
	if r.HandshakeVersion != 3 {
		t.Errorf("handshake_version=%d, want 3", r.HandshakeVersion)
	}
	if r.IsEncrypted {
		t.Error("expected is_encrypted=false for 0x03")
	}
}

func TestDecode_HandshakeS0S1_RTMPE(t *testing.T) {
	b := rtmpHandshake(0x06)
	r, err := Decode(hex.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsHandshake {
		t.Error("expected is_handshake=true")
	}
	if r.HandshakeVersion != 6 {
		t.Errorf("handshake_version=%d, want 6", r.HandshakeVersion)
	}
	if !r.IsEncrypted {
		t.Error("expected is_encrypted=true for RTMPE (0x06)")
	}
}

func TestDecode_ChunkConnectCommand(t *testing.T) {
	app := "live"
	tcURL := "rtmp://streaming.example.com/live"
	flashVer := "LNX 9,0,124,2"
	payload := buildConnectPayload(app, tcURL, flashVer)
	chunk := rtmpChunkFmt0(3, 0, 20, 0, payload)
	r, err := Decode(hex.EncodeToString(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageTypeID != 20 {
		t.Errorf("message_type_id=%d, want 20", r.MessageTypeID)
	}
	if r.MessageTypeName != "Command Message (AMF0)" {
		t.Errorf("message_type_name=%q, want Command Message (AMF0)", r.MessageTypeName)
	}
	if r.CommandName != "connect" {
		t.Errorf("command_name=%q, want connect", r.CommandName)
	}
	if !r.IsConnect {
		t.Error("expected is_connect=true")
	}
	if r.AppName != app {
		t.Errorf("app_name=%q, want %q", r.AppName, app)
	}
	if r.TcURL != tcURL {
		t.Errorf("tc_url=%q, want %q", r.TcURL, tcURL)
	}
	if r.FlashVer != flashVer {
		t.Errorf("flash_ver=%q, want %q", r.FlashVer, flashVer)
	}
}

func TestDecode_ChunkAudioMessage(t *testing.T) {
	// Audio message: type 8
	payload := []byte{0xAF, 0x00, 0x12, 0x10} // fake AAC header
	chunk := rtmpChunkFmt0(4, 1000, 8, 1, payload)
	r, err := Decode(hex.EncodeToString(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageTypeID != 8 {
		t.Errorf("message_type_id=%d, want 8", r.MessageTypeID)
	}
	if !r.IsAudio {
		t.Error("expected is_audio=true")
	}
	if r.IsVideo {
		t.Error("expected is_video=false")
	}
	if r.MessageTypeName != "Audio Message" {
		t.Errorf("message_type_name=%q, want Audio Message", r.MessageTypeName)
	}
}

func TestDecode_ChunkVideoMessage(t *testing.T) {
	payload := []byte{0x17, 0x00, 0x00, 0x00, 0x00}
	chunk := rtmpChunkFmt0(4, 2000, 9, 1, payload)
	r, err := Decode(hex.EncodeToString(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsVideo {
		t.Error("expected is_video=true")
	}
	if r.IsAudio {
		t.Error("expected is_audio=false")
	}
}

func TestDecode_ChunkPublishCommand(t *testing.T) {
	var payload []byte
	payload = append(payload, amf0String("publish")...)
	chunk := rtmpChunkFmt0(8, 0, 20, 1, payload)
	r, err := Decode(hex.EncodeToString(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if r.CommandName != "publish" {
		t.Errorf("command_name=%q, want publish", r.CommandName)
	}
	if !r.IsPublish {
		t.Error("expected is_publish=true")
	}
}

func TestDecode_ChunkPlayCommand(t *testing.T) {
	var payload []byte
	payload = append(payload, amf0String("play")...)
	chunk := rtmpChunkFmt0(8, 0, 20, 1, payload)
	r, err := Decode(hex.EncodeToString(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if r.CommandName != "play" {
		t.Errorf("command_name=%q, want play", r.CommandName)
	}
	if !r.IsPlay {
		t.Error("expected is_play=true")
	}
}

func TestDecode_ChunkControlMessage(t *testing.T) {
	// Set Chunk Size: type 1, payload is 4-byte new chunk size
	payload := []byte{0x00, 0x00, 0x10, 0x00}
	chunk := rtmpChunkFmt0(2, 0, 1, 0, payload)
	r, err := Decode(hex.EncodeToString(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if r.MessageTypeID != 1 {
		t.Errorf("message_type_id=%d, want 1", r.MessageTypeID)
	}
	if !r.IsControlMessage {
		t.Error("expected is_control_message=true")
	}
}

func TestDecode_ChunkUserControlMessage(t *testing.T) {
	// User Control Message: type 4, event_type=0 (StreamBegin) + 4-byte stream id
	payload := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	chunk := rtmpChunkFmt0(2, 0, 4, 0, payload)
	r, err := Decode(hex.EncodeToString(chunk))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsControlMessage {
		t.Error("expected is_control_message=true for type 4")
	}
	if r.UserControlEventType != 0 {
		t.Errorf("user_control_event_type=%d, want 0", r.UserControlEventType)
	}
	if r.UserControlEventName != "StreamBegin" {
		t.Errorf("user_control_event_name=%q, want StreamBegin", r.UserControlEventName)
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecode_RejectsTruncated(t *testing.T) {
	// Single byte only — not enough for any valid chunk header.
	_, err := Decode("03")
	if err == nil {
		t.Fatal("want error for single-byte input")
	}
}

func TestDecode_MessageTypeNames(t *testing.T) {
	cases := []struct {
		typeID int
		want   string
	}{
		{1, "Set Chunk Size"},
		{2, "Abort Message"},
		{3, "Acknowledgement"},
		{4, "User Control Message"},
		{5, "Window Acknowledgement Size"},
		{6, "Set Peer Bandwidth"},
		{8, "Audio Message"},
		{9, "Video Message"},
		{15, "Data Message (AMF3)"},
		{17, "Shared Object Message (AMF3)"},
		{18, "Data Message (AMF0)"},
		{19, "Shared Object Message (AMF0)"},
		{20, "Command Message (AMF0)"},
		{22, "Aggregate Message"},
	}
	for _, tc := range cases {
		got := messageTypeName(tc.typeID)
		if got != tc.want {
			t.Errorf("messageTypeName(%d)=%q, want %q", tc.typeID, got, tc.want)
		}
	}
}
