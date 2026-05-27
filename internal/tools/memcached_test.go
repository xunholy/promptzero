package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func mcHdr(magic, opcode byte, keyLen uint16, extrasLen byte, status uint16, bodyLen uint32) []byte {
	h := make([]byte, 24)
	h[0] = magic
	h[1] = opcode
	binary.BigEndian.PutUint16(h[2:4], keyLen)
	h[4] = extrasLen
	binary.BigEndian.PutUint16(h[6:8], status)
	binary.BigEndian.PutUint32(h[8:12], bodyLen)
	return h
}

// TestMemcachedDecodeHandler_GetRequest pins the cache key
// extraction for a GET operation.
func TestMemcachedDecodeHandler_GetRequest(t *testing.T) {
	key := []byte("session:abc123")
	hdr := mcHdr(0x80, 0x00, uint16(len(key)), 0, 0, uint32(len(key)))
	frame := append(hdr, key...)

	out, err := memcachedDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "Get"`,
		`"key": "session:abc123"`,
		`"is_request": true`,
		`"is_data_operation": true`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMemcachedDecodeHandler_SetRequest pins the SET operation
// with extras (flags + expiration).
func TestMemcachedDecodeHandler_SetRequest(t *testing.T) {
	key := []byte("user:42")
	value := []byte("data")
	extras := make([]byte, 8)
	binary.BigEndian.PutUint32(extras[4:8], 3600)

	bodyLen := uint32(len(extras) + len(key) + len(value))
	hdr := mcHdr(0x80, 0x01, uint16(len(key)), byte(len(extras)), 0, bodyLen)
	frame := append(hdr, extras...)
	frame = append(frame, key...)
	frame = append(frame, value...)

	out, err := memcachedDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"opcode_name": "Set"`,
		`"key": "user:42"`,
		`"expiration": 3600`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMemcachedDecodeHandler_SASLAuth pins the SASL auth
// detection.
func TestMemcachedDecodeHandler_SASLAuth(t *testing.T) {
	key := []byte("PLAIN")
	auth := []byte("\x00admin\x00secret")
	bodyLen := uint32(len(key) + len(auth))
	hdr := mcHdr(0x80, 0x21, uint16(len(key)), 0, 0, bodyLen)
	frame := append(hdr, key...)
	frame = append(frame, auth...)

	out, err := memcachedDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(frame)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"is_sasl_auth": true`,
		`"key": "PLAIN"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMemcachedDecodeHandler_VersionProbe pins version request
// classification.
func TestMemcachedDecodeHandler_VersionProbe(t *testing.T) {
	hdr := mcHdr(0x80, 0x0B, 0, 0, 0, 0)
	out, err := memcachedDecodeHandler(context.Background(), nil,
		map[string]any{"hex": hex.EncodeToString(hdr)})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"is_version_probe": true`) {
		t.Errorf("expected version_probe in output:\n%s", out)
	}
}

func TestMemcachedDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := memcachedDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
