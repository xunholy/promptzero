package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// grpcFrame builds a gRPC Length-Prefixed Message frame for tool tests.
func grpcFrame(compressed bool, payload []byte) []byte {
	var flag byte
	if compressed {
		flag = 1
	}
	out := make([]byte, 5+len(payload))
	out[0] = flag
	binary.BigEndian.PutUint32(out[1:5], uint32(len(payload)))
	copy(out[5:], payload)
	return out
}

// grpcVarint appends a protobuf base-128 varint to dst.
func grpcVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// grpcVarintField encodes a protobuf varint field (wire type 0).
func grpcVarintField(fieldNumber int, value uint64) []byte {
	tag := uint64(fieldNumber) << 3
	out := grpcVarint(nil, tag)
	return grpcVarint(out, value)
}

// grpcLenField encodes a protobuf length-delimited field (wire type 2).
func grpcLenField(fieldNumber int, data []byte) []byte {
	tag := uint64(fieldNumber)<<3 | 2
	out := grpcVarint(nil, tag)
	out = grpcVarint(out, uint64(len(data)))
	return append(out, data...)
}

// TestGRPCDecodeHandler_SingleUncompressedMessage tests a single
// uncompressed message through the handler and checks JSON output shape.
func TestGRPCDecodeHandler_SingleUncompressedMessage(t *testing.T) {
	// field 1 (varint) = 7, field 2 (length-delimited) = "grpc"
	var pb []byte
	pb = append(pb, grpcVarintField(1, 7)...)
	pb = append(pb, grpcLenField(2, []byte("grpc"))...)

	frame := grpcFrame(false, pb)
	out, err := grpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"message_count": 1`,
		`"compressed": false`,
		`"protobuf_field_count": 2`,
		`"wire_type_name": "varint"`,
		`"wire_type_name": "length-delimited"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestGRPCDecodeHandler_RejectsEmpty verifies that an empty hex input
// returns an error from the handler.
func TestGRPCDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := grpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

// TestGRPCDecodeHandler_CompressedFlag verifies the compressed flag is
// surfaced correctly in the handler JSON output.
func TestGRPCDecodeHandler_CompressedFlag(t *testing.T) {
	payload := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	frame := grpcFrame(true, payload)
	out, err := grpcDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"compressed": true`) {
		t.Errorf("expected compressed=true in output:\n%s", out)
	}
}
