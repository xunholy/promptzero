package tools

import (
	"context"
	"strings"
	"testing"
)

// TestHPACKDecodeHandler_RFC7541_C31 pins the canonical RFC 7541
// §C.3.1 first request through the Spec handler.
func TestHPACKDecodeHandler_RFC7541_C31(t *testing.T) {
	in := "8286 8441 0F77 7777 2E65 7861 6D70 6C65 2E63 6F6D"
	out, err := hpackDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"name": ":method"`, `"value": "GET"`,
		`"name": ":scheme"`, `"value": "http"`,
		`"name": ":path"`, `"value": "/"`,
		`"name": ":authority"`, `"value": "www.example.com"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestHPACKDecodeHandler_HuffmanRequest pins RFC 7541 §C.4.1 —
// the same request with Huffman-encoded :authority.
func TestHPACKDecodeHandler_HuffmanRequest(t *testing.T) {
	in := "8286 8441 8CF1 E3C2 E5F2 3A6B A0AB 90F4 FF"
	out, err := hpackDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"value": "www.example.com"`) {
		t.Errorf("expected Huffman-decoded authority:\n%s", out)
	}
}

func TestHPACKDecodeHandler_IndexedHeader(t *testing.T) {
	out, err := hpackDecodeHandler(context.Background(), nil,
		map[string]any{"hex": "82"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"representation": "indexed"`) {
		t.Errorf("expected indexed representation:\n%s", out)
	}
}

func TestHPACKDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := hpackDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
