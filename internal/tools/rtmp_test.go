package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// rtmpHandshakeBlock builds a C0+C1 / S0+S1 handshake block for
// testing: version byte + 4-byte timestamp (zero) + 4 zero bytes +
// 1528 zero bytes = 1537 bytes total.
func rtmpHandshakeBlock(version byte) []byte {
	b := make([]byte, 1537)
	b[0] = version
	return b
}

// rtmpChunkFmt0Block builds a minimal RTMP chunk with fmt=0 header
// and the given payload. cs_id must be in the range 2-63 (direct).
func rtmpChunkFmt0Block(csID byte, timestamp uint32, msgType byte, streamID uint32, payload []byte) []byte {
	msgLen := len(payload)
	var b []byte
	b = append(b, csID&0x3F) // fmt=0 (bits 7-6=00) | cs_id
	b = append(b, byte(timestamp>>16), byte(timestamp>>8), byte(timestamp))
	b = append(b, byte(msgLen>>16), byte(msgLen>>8), byte(msgLen))
	b = append(b, msgType)
	sid := make([]byte, 4)
	binary.LittleEndian.PutUint32(sid, streamID)
	b = append(b, sid...)
	b = append(b, payload...)
	return b
}

// rtmpAMF0String encodes an AMF0 string: 0x02 + 2-byte BE length + data.
func rtmpAMF0String(s string) []byte {
	b := []byte{0x02}
	lb := make([]byte, 2)
	binary.BigEndian.PutUint16(lb, uint16(len(s)))
	b = append(b, lb...)
	b = append(b, []byte(s)...)
	return b
}

// rtmpAMF0ObjKey encodes a bare AMF0 object key: 2-byte BE length + data.
func rtmpAMF0ObjKey(s string) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(s)))
	b = append(b, []byte(s)...)
	return b
}

// rtmpConnectPayload builds a minimal AMF0 "connect" command payload
// containing "app" and "tcUrl" object properties.
func rtmpConnectPayload(app, tcURL string) []byte {
	var p []byte
	// command name
	p = append(p, rtmpAMF0String("connect")...)
	// transaction ID (AMF0 number 1.0)
	p = append(p, 0x00,
		0x3F, 0xF0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// AMF0 Object marker
	p = append(p, 0x03)
	// "app" property
	p = append(p, rtmpAMF0ObjKey("app")...)
	p = append(p, rtmpAMF0String(app)...)
	// "tcUrl" property
	p = append(p, rtmpAMF0ObjKey("tcUrl")...)
	p = append(p, rtmpAMF0String(tcURL)...)
	// Object End
	p = append(p, 0x00, 0x00, 0x09)
	return p
}

// TestRTMPDecodeHandler_HandshakePlaintext tests C0+C1 handshake
// with version 0x03 (plaintext RTMP).
func TestRTMPDecodeHandler_HandshakePlaintext(t *testing.T) {
	b := rtmpHandshakeBlock(0x03)
	out, err := rtmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_handshake": true`,
		`"handshake_version": 3`,
		`"is_encrypted": false`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRTMPDecodeHandler_HandshakeRTMPE tests S0+S1 handshake with
// version 0x06 (RTMPE encrypted).
func TestRTMPDecodeHandler_HandshakeRTMPE(t *testing.T) {
	b := rtmpHandshakeBlock(0x06)
	out, err := rtmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(b)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_handshake": true`,
		`"handshake_version": 6`,
		`"is_encrypted": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRTMPDecodeHandler_ConnectCommand tests a chunk containing an
// AMF0 "connect" command with app and tcUrl fields.
func TestRTMPDecodeHandler_ConnectCommand(t *testing.T) {
	app := "live"
	tcURL := "rtmp://ingest.example.com/live"
	payload := rtmpConnectPayload(app, tcURL)
	chunk := rtmpChunkFmt0Block(3, 0, 20, 0, payload)
	out, err := rtmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(chunk)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_id": 20`,
		`"message_type_name": "Command Message (AMF0)"`,
		`"command_name": "connect"`,
		`"is_connect": true`,
		`"app_name": "live"`,
		`"tc_url": "rtmp://ingest.example.com/live"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRTMPDecodeHandler_RejectsEmpty tests that an empty hex input
// returns an error.
func TestRTMPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := rtmpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
