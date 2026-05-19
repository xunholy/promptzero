package tools

import (
	"context"
	"strings"
	"testing"
)

// TestTLSHandshakeDecodeHandler_ClientHello pins a ChangeCipherSpec
// envelope (smallest valid TLS record) through the Spec handler
// to verify the round-trip with minimal moving parts.
func TestTLSHandshakeDecodeHandler_ChangeCipherSpec(t *testing.T) {
	out, err := tlsHandshakeDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "14 03 03 00 01 01",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"content_name": "ChangeCipherSpec"`) {
		t.Errorf("expected ChangeCipherSpec:\n%s", out)
	}
	if !strings.Contains(out, `"version_name": "TLS 1.2"`) {
		t.Errorf("expected version TLS 1.2:\n%s", out)
	}
}

func TestTLSHandshakeDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := tlsHandshakeDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestTLSHandshakeDecodeHandler_RejectsTooShort(t *testing.T) {
	_, err := tlsHandshakeDecodeHandler(context.Background(), nil, map[string]any{"hex": "14 03"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
