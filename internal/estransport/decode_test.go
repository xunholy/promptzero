package estransport

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// esFrame builds a minimal ES transport frame (ES 7.x+ format):
//
//	total_size (4 BE) + "ES" marker (2) + header_size vint (1) +
//	request_id (8 BE) + status (1) + version vint (1) +
//	action (2-byte BE len prefix + bytes)
func esFrame(requestID uint64, status byte, version int, action string) []byte {
	var header []byte
	// request_id (8 BE)
	header = binary.BigEndian.AppendUint64(header, requestID)
	// status byte
	header = append(header, status)
	// transport_version (VInt — simple single-byte for small values)
	header = append(header, encodeVInt(version)...)
	// action name (2-byte BE length + bytes)
	if action != "" {
		header = binary.BigEndian.AppendUint16(header, uint16(len(action)))
		header = append(header, []byte(action)...)
	}

	// header_size vint
	var frame []byte
	frame = append(frame, encodeVInt(len(header))...)
	frame = append(frame, header...)

	// "ES" marker
	var msg []byte
	msg = append(msg, 0x45, 0x53)
	msg = append(msg, frame...)

	// total_size (4 BE) = len(msg)
	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	return append(out, msg...)
}

// encodeVInt encodes an integer as a VInt.
func encodeVInt(v int) []byte {
	if v < 0x80 {
		return []byte{byte(v)}
	}
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	b = append(b, byte(v))
	return b
}

func TestDecode_HandshakeFrame(t *testing.T) {
	// status 0x10 = handshake bit
	pkt := esFrame(1, 0x10, 800, "internal:transport/handshake")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.HasESMarker {
		t.Error("expected HasESMarker=true")
	}
	if !r.IsHandshake {
		t.Error("expected IsHandshake=true")
	}
	if !r.IsHandshakeFrame {
		t.Error("expected IsHandshakeFrame=true")
	}
	if r.ActionName != "internal:transport/handshake" {
		t.Errorf("action=%q, want internal:transport/handshake", r.ActionName)
	}
	if !r.IsInternalAction {
		t.Error("expected IsInternalAction=true for internal: prefix")
	}
	if r.RequestID != 1 {
		t.Errorf("request_id=%d, want 1", r.RequestID)
	}
}

func TestDecode_RequestFrame_StatusFlags(t *testing.T) {
	// status 0x01 = request
	pkt := esFrame(42, 0x01, 800, "indices:data/read/search")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if r.IsResponse {
		t.Error("expected IsResponse=false")
	}
	if r.IsError {
		t.Error("expected IsError=false")
	}
	if r.IsCompressed {
		t.Error("expected IsCompressed=false")
	}
	if r.ActionName != "indices:data/read/search" {
		t.Errorf("action=%q, want indices:data/read/search", r.ActionName)
	}
	if !r.IsSearch {
		t.Error("expected IsSearch=true")
	}
}

func TestDecode_ResponseFrame(t *testing.T) {
	// status 0x02 = response
	pkt := esFrame(7, 0x02, 800, "")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsResponse {
		t.Error("expected IsResponse=true")
	}
	if r.IsRequest {
		t.Error("expected IsRequest=false")
	}
}

func TestDecode_ErrorFlag(t *testing.T) {
	// status 0x06 = response (0x02) | error (0x04)
	pkt := esFrame(5, 0x06, 800, "")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsError {
		t.Error("expected IsError=true")
	}
	if !r.IsResponse {
		t.Error("expected IsResponse=true")
	}
}

func TestDecode_CompressedFlag(t *testing.T) {
	// status 0x09 = request (0x01) | compressed (0x08)
	pkt := esFrame(3, 0x09, 800, "indices:data/write/index")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsCompressed {
		t.Error("expected IsCompressed=true")
	}
	if !r.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if !r.IsIndex {
		t.Error("expected IsIndex=true")
	}
}

func TestDecode_ClusterStateAction(t *testing.T) {
	pkt := esFrame(10, 0x01, 800, "internal:cluster/state")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsClusterState {
		t.Error("expected IsClusterState=true")
	}
	if !r.IsInternalAction {
		t.Error("expected IsInternalAction=true")
	}
}

func TestDecode_IndexAdminAction(t *testing.T) {
	pkt := esFrame(11, 0x01, 800, "indices:admin/create")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsIndex {
		t.Error("expected IsIndex=true for indices:admin/create")
	}
}

func TestDecode_TotalBytesAndMessageSize(t *testing.T) {
	pkt := esFrame(99, 0x01, 800, "cluster:monitor/nodes/info")
	r, err := Decode(hex.EncodeToString(pkt))
	if err != nil {
		t.Fatal(err)
	}
	if r.TotalBytes != len(pkt) {
		t.Errorf("total_bytes=%d, want %d", r.TotalBytes, len(pkt))
	}
	if r.MessageSize == 0 {
		t.Error("expected non-zero MessageSize")
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("0102030405")
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}

func TestDecode_RejectsMissingESMarker(t *testing.T) {
	// 4-byte size + 2 wrong marker bytes + padding
	b := make([]byte, minFrameSize)
	binary.BigEndian.PutUint32(b[0:4], uint32(minFrameSize-4))
	b[4] = 0xAA
	b[5] = 0xBB
	_, err := Decode(hex.EncodeToString(b))
	if err == nil {
		t.Fatal("want error for missing ES magic marker")
	}
}

func TestDecode_SeparatorsStripped(t *testing.T) {
	pkt := esFrame(1, 0x10, 800, "internal:transport/handshake")
	raw := hex.EncodeToString(pkt)
	// Insert colons as separators
	separated := raw[:4] + ":" + raw[4:8] + ":" + raw[8:]
	r, err := Decode(separated)
	if err != nil {
		t.Fatalf("separator-stripped decode: %v", err)
	}
	if !r.HasESMarker {
		t.Error("expected HasESMarker=true with separators")
	}
}
