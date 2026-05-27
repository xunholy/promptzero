package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// eigrpHello builds a minimal EIGRP Hello packet with a Parameters TLV.
// version=2, opcode=5 (Hello), no flags, seq=0, ack=0, vrID=0, as=asNum.
// Parameters TLV: K1=1 K2=0 K3=1 K4=0 K5=0, holdTime=15.
func eigrpHello(asNum uint16) []byte {
	hdr := make([]byte, 20)
	hdr[0] = 2 // version
	hdr[1] = 5 // opcode Hello
	// flags [4:8] = 0
	// seq [8:12] = 0
	// ack [12:16] = 0
	// vrID [16:18] = 0
	binary.BigEndian.PutUint16(hdr[18:20], asNum)

	// Parameters TLV (type 0x0001, length 11)
	tlv := make([]byte, 11)
	binary.BigEndian.PutUint16(tlv[0:2], 0x0001) // type
	binary.BigEndian.PutUint16(tlv[2:4], 11)     // length
	tlv[4] = 1                                   // K1
	tlv[5] = 0                                   // K2
	tlv[6] = 1                                   // K3
	tlv[7] = 0                                   // K4
	tlv[8] = 0                                   // K5
	binary.BigEndian.PutUint16(tlv[9:11], 15)    // hold_time

	return append(hdr, tlv...)
}

// TestEIGRPDecodeHandler_Hello pins the canonical EIGRP Hello shape through
// the handler — AS number, opcode name, K-values, hold time.
func TestEIGRPDecodeHandler_Hello(t *testing.T) {
	pkt := eigrpHello(100)
	out, err := eigrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "Hello"`,
		`"autonomous_system": 100`,
		`"is_hello": true`,
		`"k1": 1`,
		`"k3": 1`,
		`"hold_time": 15`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestEIGRPDecodeHandler_RejectsEmpty confirms the handler returns an error
// when the hex parameter is empty.
func TestEIGRPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := eigrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

// TestEIGRPDecodeHandler_RejectsTruncated confirms that a buffer shorter than
// the 20-byte EIGRP header is rejected.
func TestEIGRPDecodeHandler_RejectsTruncated(t *testing.T) {
	_, err := eigrpDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "02050000"})
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
