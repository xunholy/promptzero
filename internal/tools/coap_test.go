package tools

import (
	"context"
	"strings"
	"testing"
)

// TestCoAPDecodeHandler_GET confirms the Spec handler decodes
// a typical CoAP GET request with Uri-Path option through to
// JSON.
func TestCoAPDecodeHandler_GET(t *testing.T) {
	out, err := coapPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "40 01 12 34 B7 73 65 6E 73 6F 72 73",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"code_name": "GET"`) {
		t.Errorf("expected GET code name:\n%s", out)
	}
	if !strings.Contains(out, `"name": "Uri-Path"`) {
		t.Errorf("expected Uri-Path option:\n%s", out)
	}
	if !strings.Contains(out, `"value_string": "sensors"`) {
		t.Errorf("expected value sensors:\n%s", out)
	}
}

// TestCoAPDecodeHandler_2_05Content pins a CoAP Content
// response with JSON payload.
func TestCoAPDecodeHandler_2_05Content(t *testing.T) {
	out, err := coapPacketDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "62 45 56 78 AA BB C1 32 FF 7B 22 76 22 3A 34 32 7D",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"code_text": "2.05"`) {
		t.Errorf("expected 2.05 code text:\n%s", out)
	}
	if !strings.Contains(out, `"payload_string": "{\"v\":42}"`) {
		t.Errorf("expected JSON payload string:\n%s", out)
	}
}

func TestCoAPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := coapPacketDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
