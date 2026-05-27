package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// ldpHelloPDU builds a minimal LDP Hello PDU with a Common Hello Parameters
// TLV. version=1, lsrID provided, labelSpace=0, msgID=1.
// Common Hello Parameters: holdTime=15s, link Hello (not targeted).
func ldpHelloPDU(lsrID [4]byte) []byte {
	// Common Hello Parameters TLV (type 0x0500, length 4):
	// hold_time(2) + flags(2)
	helloTLV := make([]byte, 8)
	binary.BigEndian.PutUint16(helloTLV[0:2], 0x0500)
	binary.BigEndian.PutUint16(helloTLV[2:4], 4)  // value length
	binary.BigEndian.PutUint16(helloTLV[4:6], 15) // hold_time = 15s
	// flags = 0 (link Hello, not targeted)

	// IPv4 Transport Address TLV (type 0x0501, length 4)
	transportTLV := make([]byte, 8)
	binary.BigEndian.PutUint16(transportTLV[0:2], 0x0501)
	binary.BigEndian.PutUint16(transportTLV[2:4], 4)
	copy(transportTLV[4:8], lsrID[:])

	tlvs := append(helloTLV, transportTLV...)

	// Message header: type=0x0100 Hello, length=4+len(tlvs), id=1
	msgLength := uint16(4 + len(tlvs))
	msg := make([]byte, 8)
	binary.BigEndian.PutUint16(msg[0:2], 0x0100)
	binary.BigEndian.PutUint16(msg[2:4], msgLength)
	binary.BigEndian.PutUint32(msg[4:8], 1)
	msg = append(msg, tlvs...)

	// PDU header: version=1, pduLength=6+len(msg)
	pduLength := uint16(6 + len(msg))
	pdu := make([]byte, 10)
	binary.BigEndian.PutUint16(pdu[0:2], 1)
	binary.BigEndian.PutUint16(pdu[2:4], pduLength)
	copy(pdu[4:8], lsrID[:])
	// labelSpace[8:10] = 0
	return append(pdu, msg...)
}

// TestLDPDecodeHandler_Hello pins the canonical LDP Hello shape through the
// handler — LSR ID, message type name, hold time, transport address.
func TestLDPDecodeHandler_Hello(t *testing.T) {
	lsrID := [4]byte{10, 0, 0, 1}
	pkt := ldpHelloPDU(lsrID)
	out, err := ldpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_type_name": "Hello"`,
		`"lsr_id": "10.0.0.1"`,
		`"is_hello": true`,
		`"hold_time": 15`,
		`"transport_address": "10.0.0.1"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLDPDecodeHandler_RejectsEmpty confirms the handler returns an error
// when the hex parameter is empty.
func TestLDPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ldpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

// TestLDPDecodeHandler_RejectsTruncated confirms that a buffer shorter than
// the 10-byte LDP PDU header is rejected.
func TestLDPDecodeHandler_RejectsTruncated(t *testing.T) {
	_, err := ldpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "00010000"}) // 4 bytes, below 10
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
