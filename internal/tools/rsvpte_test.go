package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// rsvptePathPacket builds a minimal RSVP-TE Path packet with a SESSION object
// (C-Type 7 LSP_TUNNEL_IPv4) and a SENDER_TEMPLATE object (C-Type 7).
// Used to exercise the handler without duplicating the full builder from the
// internal/rsvpte decode_test.go.
func rsvptePathPacket() []byte {
	// 8-byte RSVP common header: version=1, flags=0, msg_type=1 (Path),
	// checksum=0, send_ttl=64, reserved=0, rsvp_length set below.
	hdr := make([]byte, 8)
	hdr[0] = 0x10 // version=1, flags=0
	hdr[1] = 0x01 // msg_type = Path
	// checksum [2:4] = 0
	hdr[4] = 64 // send_ttl
	// reserved [5] = 0

	// SESSION object (class=1, c_type=7): LSP_TUNNEL_IPv4
	// value = endpoint(4) + reserved(2) + tunnel_id(2) + ext_tunnel_id(4) = 12 bytes
	// total object = 4 + 12 = 16 bytes
	sessObj := make([]byte, 16)
	binary.BigEndian.PutUint16(sessObj[0:2], 16) // length
	sessObj[2] = 1                               // class_num = SESSION
	sessObj[3] = 7                               // c_type = LSP_TUNNEL_IPv4
	sessObj[4] = 172                             // endpoint 172.16.1.1
	sessObj[5] = 16
	sessObj[6] = 1
	sessObj[7] = 1
	// sessObj[8:10] = reserved
	binary.BigEndian.PutUint16(sessObj[10:12], 1001) // tunnel_id
	sessObj[12] = 10                                 // ext_tunnel_id 10.0.0.5
	sessObj[13] = 0
	sessObj[14] = 0
	sessObj[15] = 5

	// SENDER_TEMPLATE object (class=11, c_type=7): LSP_TUNNEL_IPv4
	// value = sender(4) + reserved(2) + lsp_id(2) = 8 bytes
	// total object = 4 + 8 = 12 bytes
	stObj := make([]byte, 12)
	binary.BigEndian.PutUint16(stObj[0:2], 12) // length
	stObj[2] = 11                              // class_num = SENDER_TEMPLATE
	stObj[3] = 7                               // c_type = LSP_TUNNEL_IPv4
	stObj[4] = 10                              // sender 10.0.0.5
	stObj[5] = 0
	stObj[6] = 0
	stObj[7] = 5
	// stObj[8:10] = reserved
	binary.BigEndian.PutUint16(stObj[10:12], 200) // lsp_id

	var body []byte
	body = append(body, sessObj...)
	body = append(body, stObj...)

	totalLen := uint16(8 + len(body))
	binary.BigEndian.PutUint16(hdr[6:8], totalLen)

	return append(hdr, body...)
}

// TestRSVPTEDecodeHandler_Path pins the canonical RSVP-TE Path packet shape
// through the handler — msg_type_name, is_path, SESSION fields, SENDER_TEMPLATE
// fields, and object_count.
func TestRSVPTEDecodeHandler_Path(t *testing.T) {
	pkt := rsvptePathPacket()
	out, err := rsvpteDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"msg_type_name": "Path"`,
		`"is_path": true`,
		`"tunnel_endpoint": "172.16.1.1"`,
		`"tunnel_id": 1001`,
		`"extended_tunnel_id": "10.0.0.5"`,
		`"sender_address": "10.0.0.5"`,
		`"lsp_id": 200`,
		`"object_count": 2`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestRSVPTEDecodeHandler_RejectsEmpty confirms the handler returns an error
// when the hex parameter is empty.
func TestRSVPTEDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := rsvpteDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

// TestRSVPTEDecodeHandler_RejectsTruncated confirms that a buffer shorter than
// the 8-byte RSVP header is rejected.
func TestRSVPTEDecodeHandler_RejectsTruncated(t *testing.T) {
	_, err := rsvpteDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "10010000"}) // 4 bytes, below 8-byte minimum
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
