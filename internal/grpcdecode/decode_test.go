package grpcdecode

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// grpcFrame builds a gRPC Length-Prefixed Message frame.
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

// appendVarint appends a protobuf base-128 varint to dst.
func appendVarint(dst []byte, v uint64) []byte {
	for v >= 0x80 {
		dst = append(dst, byte(v)|0x80)
		v >>= 7
	}
	return append(dst, byte(v))
}

// protoFieldTag returns the varint-encoded field tag for a protobuf field.
func protoFieldTag(fieldNumber int, wireType int) []byte {
	tag := uint64(fieldNumber)<<3 | uint64(wireType)
	return appendVarint(nil, tag)
}

// protoVarintField encodes a protobuf varint field (wire type 0).
func protoVarintField(fieldNumber int, value uint64) []byte {
	out := protoFieldTag(fieldNumber, 0)
	return appendVarint(out, value)
}

// protoLenField encodes a protobuf length-delimited field (wire type 2).
func protoLenField(fieldNumber int, data []byte) []byte {
	out := protoFieldTag(fieldNumber, 2)
	out = appendVarint(out, uint64(len(data)))
	return append(out, data...)
}

// proto32BitField encodes a protobuf 32-bit fixed field (wire type 5).
func proto32BitField(fieldNumber int) []byte {
	out := protoFieldTag(fieldNumber, 5)
	return append(out, 0, 0, 0, 0)
}

// TestDecode_SingleUncompressedMessage tests a single uncompressed message
// with a few protobuf fields.
func TestDecode_SingleUncompressedMessage(t *testing.T) {
	// Build a protobuf payload with three fields:
	//   field 1 (varint)            = 42
	//   field 2 (length-delimited)  = "hello"
	//   field 3 (varint)            = 1
	var pb []byte
	pb = append(pb, protoVarintField(1, 42)...)
	pb = append(pb, protoLenField(2, []byte("hello"))...)
	pb = append(pb, protoVarintField(3, 1)...)

	frame := grpcFrame(false, pb)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.TotalBytes != len(frame) {
		t.Errorf("total_bytes=%d, want %d", r.TotalBytes, len(frame))
	}
	if r.MessageCount != 1 {
		t.Errorf("message_count=%d, want 1", r.MessageCount)
	}
	msg := r.Messages[0]
	if msg.Compressed {
		t.Error("compressed=true, want false")
	}
	if msg.MessageLength != len(pb) {
		t.Errorf("message_length=%d, want %d", msg.MessageLength, len(pb))
	}
	if msg.ProtobufFieldCount != 3 {
		t.Errorf("protobuf_field_count=%d, want 3", msg.ProtobufFieldCount)
	}
	if len(msg.ProtobufFields) < 3 {
		t.Fatalf("protobuf_fields length=%d, want >=3", len(msg.ProtobufFields))
	}
	if msg.ProtobufFields[0].FieldNumber != 1 {
		t.Errorf("fields[0].field_number=%d, want 1", msg.ProtobufFields[0].FieldNumber)
	}
	if msg.ProtobufFields[0].WireType != 0 {
		t.Errorf("fields[0].wire_type=%d, want 0", msg.ProtobufFields[0].WireType)
	}
	if msg.ProtobufFields[0].WireTypeName != "varint" {
		t.Errorf("fields[0].wire_type_name=%q, want varint", msg.ProtobufFields[0].WireTypeName)
	}
	if msg.ProtobufFields[1].FieldNumber != 2 {
		t.Errorf("fields[1].field_number=%d, want 2", msg.ProtobufFields[1].FieldNumber)
	}
	if msg.ProtobufFields[1].WireType != 2 {
		t.Errorf("fields[1].wire_type=%d, want 2", msg.ProtobufFields[1].WireType)
	}
	if msg.ProtobufFields[1].WireTypeName != "length-delimited" {
		t.Errorf("fields[1].wire_type_name=%q, want length-delimited", msg.ProtobufFields[1].WireTypeName)
	}
	if msg.ProtobufFields[2].FieldNumber != 3 {
		t.Errorf("fields[2].field_number=%d, want 3", msg.ProtobufFields[2].FieldNumber)
	}
}

// TestDecode_CompressedFlag tests that a message with compressed_flag=1
// is decoded correctly (header only; payload is not decompressed).
func TestDecode_CompressedFlag(t *testing.T) {
	// Payload is opaque (would be gzip-compressed in real traffic).
	payload := []byte{0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00}
	frame := grpcFrame(true, payload)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageCount != 1 {
		t.Errorf("message_count=%d, want 1", r.MessageCount)
	}
	msg := r.Messages[0]
	if !msg.Compressed {
		t.Error("compressed=false, want true")
	}
	if msg.MessageLength != len(payload) {
		t.Errorf("message_length=%d, want %d", msg.MessageLength, len(payload))
	}
	// Compressed messages do not have protobuf fields scanned.
	if msg.ProtobufFieldCount != 0 {
		t.Errorf("protobuf_field_count=%d, want 0 (compressed)", msg.ProtobufFieldCount)
	}
}

// TestDecode_MultipleMessages tests a streaming gRPC payload with two
// concatenated length-prefixed messages.
func TestDecode_MultipleMessages(t *testing.T) {
	// First message: field 1 (varint) = 100
	var pb1 []byte
	pb1 = append(pb1, protoVarintField(1, 100)...)

	// Second message: field 1 (varint) = 200, field 2 (32-bit fixed)
	var pb2 []byte
	pb2 = append(pb2, protoVarintField(1, 200)...)
	pb2 = append(pb2, proto32BitField(2)...)

	frame := append(grpcFrame(false, pb1), grpcFrame(false, pb2)...)
	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.MessageCount != 2 {
		t.Errorf("message_count=%d, want 2", r.MessageCount)
	}
	if r.TotalBytes != len(frame) {
		t.Errorf("total_bytes=%d, want %d", r.TotalBytes, len(frame))
	}
	// First message
	m0 := r.Messages[0]
	if m0.MessageLength != len(pb1) {
		t.Errorf("messages[0].message_length=%d, want %d", m0.MessageLength, len(pb1))
	}
	if m0.ProtobufFieldCount != 1 {
		t.Errorf("messages[0].protobuf_field_count=%d, want 1", m0.ProtobufFieldCount)
	}
	// Second message
	m1 := r.Messages[1]
	if m1.MessageLength != len(pb2) {
		t.Errorf("messages[1].message_length=%d, want %d", m1.MessageLength, len(pb2))
	}
	if m1.ProtobufFieldCount != 2 {
		t.Errorf("messages[1].protobuf_field_count=%d, want 2", m1.ProtobufFieldCount)
	}
	if len(m1.ProtobufFields) < 2 {
		t.Fatalf("messages[1].protobuf_fields length=%d, want >=2", len(m1.ProtobufFields))
	}
	if m1.ProtobufFields[1].WireType != 5 {
		t.Errorf("messages[1].fields[1].wire_type=%d, want 5", m1.ProtobufFields[1].WireType)
	}
	if m1.ProtobufFields[1].WireTypeName != "32-bit" {
		t.Errorf("messages[1].fields[1].wire_type_name=%q, want 32-bit", m1.ProtobufFields[1].WireTypeName)
	}
}

// TestDecode_RejectsEmpty verifies that an empty hex string is rejected.
func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

// TestDecode_RejectsTruncated verifies that a 4-byte (truncated) input is
// rejected since a valid gRPC header requires at least 5 bytes.
func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("0000000a") // 4 bytes — missing 1 byte for the header
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}

// TestGRPCStatusName verifies the status code lookup table.
func TestGRPCStatusName(t *testing.T) {
	cases := []struct {
		code int
		name string
	}{
		{0, "OK"},
		{1, "CANCELLED"},
		{2, "UNKNOWN"},
		{3, "INVALID_ARGUMENT"},
		{4, "DEADLINE_EXCEEDED"},
		{5, "NOT_FOUND"},
		{6, "ALREADY_EXISTS"},
		{7, "PERMISSION_DENIED"},
		{8, "RESOURCE_EXHAUSTED"},
		{9, "FAILED_PRECONDITION"},
		{10, "ABORTED"},
		{11, "OUT_OF_RANGE"},
		{12, "UNIMPLEMENTED"},
		{13, "INTERNAL"},
		{14, "UNAVAILABLE"},
		{15, "DATA_LOSS"},
		{16, "UNAUTHENTICATED"},
		{99, "grpc_status_99"},
	}
	for _, tc := range cases {
		got := GRPCStatusName(tc.code)
		if got != tc.name {
			t.Errorf("GRPCStatusName(%d)=%q, want %q", tc.code, got, tc.name)
		}
	}
}
