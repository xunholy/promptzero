package tools

import (
	"context"
	"strings"
	"testing"
)

// llmnrEncodeName mirrors the test helper from internal/llmnr.
func llmnrEncodeName(s string) string {
	const digits = "0123456789ABCDEF"
	var out []byte
	for _, label := range strings.Split(s, ".") {
		out = append(out, byte(len(label)))
		out = append(out, []byte(label)...)
	}
	out = append(out, 0x00)
	hex := make([]byte, len(out)*2)
	for i, v := range out {
		hex[i*2] = digits[v>>4]
		hex[i*2+1] = digits[v&0x0F]
	}
	return string(hex)
}

// TestLLMNRDecodeHandler_QueryA pins the canonical LLMNR A
// query for a short hostname — the Responder.py trigger.
func TestLLMNRDecodeHandler_QueryA(t *testing.T) {
	enc := llmnrEncodeName("fileserv1")
	in := "1234 0000 0001 0000 0000 0000 " +
		enc + " 0001 0001"
	out, err := llmnrDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"transaction_id": 4660`,
		`"opcode_name": "LLMNR_QUERY"`,
		`"name": "fileserv1"`,
		`"type_name": "A"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLLMNRDecodeHandler_ResponseWithIP pins the
// Responder.py-style poisoned reply.
func TestLLMNRDecodeHandler_ResponseWithIP(t *testing.T) {
	enc := llmnrEncodeName("fileserv1")
	in := "1234 8000 0001 0001 0000 0000 " +
		enc + " 0001 0001 " +
		enc + " 0001 0001 0000001E 0004 C0A80164"
	out, err := llmnrDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"qr_response": true`,
		`"ipv4": "192.168.1.100"`,
		`"ttl": 30`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestLLMNRDecodeHandler_RejectsCompression asserts the
// RFC-4795-§2.1.7 "no compression pointers" constraint is
// enforced.
func TestLLMNRDecodeHandler_RejectsCompression(t *testing.T) {
	// Question name pointer 0xC0 0x0C (illegal in LLMNR).
	in := "1111 0000 0001 0000 0000 0000 C00C 0001 0001"
	_, err := llmnrDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err == nil {
		t.Fatal("want error for compression pointer in LLMNR message")
	}
	if !strings.Contains(err.Error(), "compression pointer") {
		t.Errorf("expected compression-pointer error, got %v", err)
	}
}

func TestLLMNRDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := llmnrDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
