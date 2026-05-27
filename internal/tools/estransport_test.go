package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// esTransportFrame builds a minimal ES transport frame for testing.
// Format: total_size(4 BE) + "ES"(2) + header_size_vint(1) +
// request_id(8 BE) + status(1) + version_vint(1) +
// action_len(2 BE) + action_bytes.
func esTransportFrame(requestID uint64, status byte, version int, action string) []byte {
	var header []byte
	header = binary.BigEndian.AppendUint64(header, requestID)
	header = append(header, status)
	header = append(header, esVInt(version)...)
	if action != "" {
		header = binary.BigEndian.AppendUint16(header, uint16(len(action)))
		header = append(header, []byte(action)...)
	}

	var frame []byte
	frame = append(frame, esVInt(len(header))...)
	frame = append(frame, header...)

	var msg []byte
	msg = append(msg, 0x45, 0x53) // "ES" marker
	msg = append(msg, frame...)

	out := make([]byte, 4)
	binary.BigEndian.PutUint32(out, uint32(len(msg)))
	return append(out, msg...)
}

// esVInt encodes an integer as a VInt.
func esVInt(v int) []byte {
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

// TestESTransportDecodeHandler_Handshake pins the transport handshake shape.
func TestESTransportDecodeHandler_Handshake(t *testing.T) {
	pkt := esTransportFrame(1, 0x10, 800, "internal:transport/handshake")
	out, err := esTransportDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"has_es_marker": true`,
		`"is_handshake": true`,
		`"action_name": "internal:transport/handshake"`,
		`"is_internal_action": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestESTransportDecodeHandler_SearchRequest pins the search request shape.
func TestESTransportDecodeHandler_SearchRequest(t *testing.T) {
	// status 0x01 = request
	pkt := esTransportFrame(42, 0x01, 800, "indices:data/read/search")
	out, err := esTransportDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"has_es_marker": true`,
		`"is_request": true`,
		`"action_name": "indices:data/read/search"`,
		`"is_search": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestESTransportDecodeHandler_ClusterState pins the cluster state action.
func TestESTransportDecodeHandler_ClusterState(t *testing.T) {
	pkt := esTransportFrame(10, 0x01, 800, "internal:cluster/state")
	out, err := esTransportDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_cluster_state": true`,
		`"is_internal_action": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestESTransportDecodeHandler_StatusFlags pins multi-bit status flag decoding.
func TestESTransportDecodeHandler_StatusFlags(t *testing.T) {
	// status 0x0C = compressed (0x08) | error (0x04)
	pkt := esTransportFrame(5, 0x0C, 800, "")
	out, err := esTransportDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(pkt)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_error": true`,
		`"is_compressed": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestESTransportDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := esTransportDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
