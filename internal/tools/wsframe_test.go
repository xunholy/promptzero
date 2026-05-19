package tools

import (
	"context"
	"strings"
	"testing"
)

// TestWebsocketFrameDecodeHandler_ServerText pins a canonical
// server-side Text "Hello" through the Spec handler.
func TestWebsocketFrameDecodeHandler_ServerText(t *testing.T) {
	in := "8105 48656C6C6F"
	out, err := websocketFrameDecodeHandler(context.Background(), nil, map[string]any{
		"hex": in,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"opcode_name": "Text"`) {
		t.Errorf("expected Text opcode:\n%s", out)
	}
	if !strings.Contains(out, `"payload_text": "Hello"`) {
		t.Errorf("expected payload text Hello:\n%s", out)
	}
}

// TestWebsocketFrameDecodeHandler_ClientMasked pins the
// canonical RFC 6455 §5.7 masked-client example.
func TestWebsocketFrameDecodeHandler_ClientMasked(t *testing.T) {
	in := "8185 37FA213D 7F9F4D5158"
	out, err := websocketFrameDecodeHandler(context.Background(), nil, map[string]any{
		"hex": in,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"masked": true`) {
		t.Errorf("expected masked true:\n%s", out)
	}
	if !strings.Contains(out, `"mask_key": "37FA213D"`) {
		t.Errorf("expected mask key:\n%s", out)
	}
	if !strings.Contains(out, `"payload_text": "Hello"`) {
		t.Errorf("expected demasked Hello:\n%s", out)
	}
}

// TestWebsocketFrameDecodeHandler_CloseWithReason pins a close
// frame with status 1000 + reason "bye".
func TestWebsocketFrameDecodeHandler_CloseWithReason(t *testing.T) {
	in := "8805 03E8 627965"
	out, err := websocketFrameDecodeHandler(context.Background(), nil, map[string]any{
		"hex": in,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"status_code": 1000`) {
		t.Errorf("expected status_code 1000:\n%s", out)
	}
	if !strings.Contains(out, `"status_name": "Normal Closure"`) {
		t.Errorf("expected status name:\n%s", out)
	}
	if !strings.Contains(out, `"reason": "bye"`) {
		t.Errorf("expected reason bye:\n%s", out)
	}
}

func TestWebsocketFrameDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := websocketFrameDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
