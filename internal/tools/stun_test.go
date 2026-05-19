package tools

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// TestSTUNPacketDecodeHandler_BindingRequest pins a minimal
// STUN Binding Request through the Spec handler.
func TestSTUNPacketDecodeHandler_BindingRequest(t *testing.T) {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], 0x0001) // Binding Request
	binary.BigEndian.PutUint32(hdr[4:8], 0x2112A442)
	for i := 8; i < 20; i++ {
		hdr[i] = byte(i)
	}
	out, err := stunPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex.EncodeToString(hdr),
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"method_name": "Binding"`) {
		t.Errorf("expected method_name Binding:\n%s", out)
	}
	if !strings.Contains(out, `"message_class_name": "Request"`) {
		t.Errorf("expected message_class_name Request:\n%s", out)
	}
	if !strings.Contains(out, `"magic_cookie_hex": "0x2112A442"`) {
		t.Errorf("expected magic_cookie_hex:\n%s", out)
	}
}

func TestSTUNPacketDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := stunPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestSTUNPacketDecodeHandler_RejectsBadMagicCookie(t *testing.T) {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint32(hdr[4:8], 0xDEADBEEF)
	_, err := stunPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": hex.EncodeToString(hdr),
	})
	if err == nil {
		t.Fatal("want error for bad magic cookie")
	}
}
