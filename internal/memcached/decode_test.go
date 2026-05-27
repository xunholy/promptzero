package memcached

import (
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func mcHeader(magic, opcode byte, keyLen uint16, extrasLen byte, status uint16, bodyLen uint32, opaque uint32, cas uint64) []byte {
	h := make([]byte, 24)
	h[0] = magic
	h[1] = opcode
	binary.BigEndian.PutUint16(h[2:4], keyLen)
	h[4] = extrasLen
	h[5] = 0 // data_type
	binary.BigEndian.PutUint16(h[6:8], status)
	binary.BigEndian.PutUint32(h[8:12], bodyLen)
	binary.BigEndian.PutUint32(h[12:16], opaque)
	binary.BigEndian.PutUint64(h[16:24], cas)
	return h
}

func TestDecode_GetRequest(t *testing.T) {
	key := []byte("session:abc123")
	hdr := mcHeader(0x80, 0x00, uint16(len(key)), 0, 0, uint32(len(key)), 0, 0)
	frame := append(hdr, key...)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsRequest {
		t.Error("expected IsRequest=true")
	}
	if r.OpcodeName != "Get" {
		t.Errorf("opcode=%q, want Get", r.OpcodeName)
	}
	if r.Key != "session:abc123" {
		t.Errorf("key=%q, want session:abc123", r.Key)
	}
	if !r.IsDataOp {
		t.Error("expected IsDataOp=true")
	}
}

func TestDecode_SetRequest(t *testing.T) {
	key := []byte("user:42:profile")
	value := []byte(`{"name":"Alice"}`)
	extras := make([]byte, 8)
	binary.BigEndian.PutUint32(extras[0:4], 0)    // flags
	binary.BigEndian.PutUint32(extras[4:8], 3600) // expiration

	bodyLen := uint32(len(extras) + len(key) + len(value))
	hdr := mcHeader(0x80, 0x01, uint16(len(key)), byte(len(extras)), 0, bodyLen, 0, 0)
	frame := append(hdr, extras...)
	frame = append(frame, key...)
	frame = append(frame, value...)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Set" {
		t.Errorf("opcode=%q, want Set", r.OpcodeName)
	}
	if r.Key != "user:42:profile" {
		t.Errorf("key=%q, want user:42:profile", r.Key)
	}
	if r.Expiration != 3600 {
		t.Errorf("expiration=%d, want 3600", r.Expiration)
	}
	if r.ValueLength != len(value) {
		t.Errorf("value_length=%d, want %d", r.ValueLength, len(value))
	}
}

func TestDecode_IncrementRequest(t *testing.T) {
	key := []byte("counter:visits")
	extras := make([]byte, 20)
	binary.BigEndian.PutUint64(extras[0:8], 1)   // delta
	binary.BigEndian.PutUint64(extras[8:16], 0)  // initial
	binary.BigEndian.PutUint32(extras[16:20], 0) // expiration

	bodyLen := uint32(len(extras) + len(key))
	hdr := mcHeader(0x80, 0x05, uint16(len(key)), byte(len(extras)), 0, bodyLen, 0, 0)
	frame := append(hdr, extras...)
	frame = append(frame, key...)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Increment" {
		t.Errorf("opcode=%q, want Increment", r.OpcodeName)
	}
	if r.Delta != 1 {
		t.Errorf("delta=%d, want 1", r.Delta)
	}
	if r.Key != "counter:visits" {
		t.Errorf("key=%q, want counter:visits", r.Key)
	}
}

func TestDecode_DeleteRequest(t *testing.T) {
	key := []byte("expired:token")
	hdr := mcHeader(0x80, 0x04, uint16(len(key)), 0, 0, uint32(len(key)), 0, 0)
	frame := append(hdr, key...)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Delete" {
		t.Errorf("opcode=%q, want Delete", r.OpcodeName)
	}
	if r.Key != "expired:token" {
		t.Errorf("key=%q, want expired:token", r.Key)
	}
}

func TestDecode_Response(t *testing.T) {
	hdr := mcHeader(0x81, 0x00, 0, 0, 0x0001, 0, 0, 0)
	r, err := Decode(hex.EncodeToString(hdr))
	if err != nil {
		t.Fatal(err)
	}
	if !r.IsResponse {
		t.Error("expected IsResponse=true")
	}
	if r.StatusName != "Key not found" {
		t.Errorf("status=%q, want 'Key not found'", r.StatusName)
	}
}

func TestDecode_VersionRequest(t *testing.T) {
	hdr := mcHeader(0x80, 0x0B, 0, 0, 0, 0, 0, 0)
	r, err := Decode(hex.EncodeToString(hdr))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Version" {
		t.Errorf("opcode=%q, want Version", r.OpcodeName)
	}
	if !r.IsVersionProbe {
		t.Error("expected IsVersionProbe=true")
	}
}

func TestDecode_StatRequest(t *testing.T) {
	hdr := mcHeader(0x80, 0x10, 0, 0, 0, 0, 0, 0)
	r, err := Decode(hex.EncodeToString(hdr))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Stat" {
		t.Errorf("opcode=%q, want Stat", r.OpcodeName)
	}
	if !r.IsAdminOp {
		t.Error("expected IsAdminOp=true")
	}
}

func TestDecode_SASLAuth(t *testing.T) {
	key := []byte("PLAIN")
	auth := []byte("\x00admin\x00secret")
	bodyLen := uint32(len(key) + len(auth))
	hdr := mcHeader(0x80, 0x21, uint16(len(key)), 0, 0, bodyLen, 0, 0)
	frame := append(hdr, key...)
	frame = append(frame, auth...)

	r, err := Decode(hex.EncodeToString(frame))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "SASL Authenticate" {
		t.Errorf("opcode=%q, want 'SASL Authenticate'", r.OpcodeName)
	}
	if !r.IsSASLAuth {
		t.Error("expected IsSASLAuth=true")
	}
	if r.Key != "PLAIN" {
		t.Errorf("key=%q, want PLAIN (mechanism name)", r.Key)
	}
	if r.AuthBytes != len(auth) {
		t.Errorf("auth_bytes=%d, want %d", r.AuthBytes, len(auth))
	}
}

func TestDecode_FlushRequest(t *testing.T) {
	hdr := mcHeader(0x80, 0x08, 0, 0, 0, 0, 0, 0)
	r, err := Decode(hex.EncodeToString(hdr))
	if err != nil {
		t.Fatal(err)
	}
	if r.OpcodeName != "Flush" {
		t.Errorf("opcode=%q, want Flush", r.OpcodeName)
	}
	if !r.IsAdminOp {
		t.Error("expected IsAdminOp=true")
	}
}

func TestDecode_RejectsEmpty(t *testing.T) {
	_, err := Decode("")
	if err == nil {
		t.Fatal("want error for empty input")
	}
}

func TestDecode_RejectsTruncated(t *testing.T) {
	_, err := Decode("8001")
	if err == nil {
		t.Fatal("want error for truncated input")
	}
}
