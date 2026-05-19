package tools

import (
	"context"
	"strings"
	"testing"
)

// TestCBORDecodeHandler_Map pins a simple CBOR map through
// the Spec handler.
func TestCBORDecodeHandler_Map(t *testing.T) {
	// {"hello": 42}
	// A1 (map of 1) + 65 (text len 5) + "hello" + 18 2A (24 + 42)
	out, err := cborDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "A165 68656C6C6F 18 2A",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"major_name": "Map"`) {
		t.Errorf("expected major_name Map:\n%s", out)
	}
	if !strings.Contains(out, `"text": "hello"`) {
		t.Errorf("expected text hello:\n%s", out)
	}
	if !strings.Contains(out, `"uint": 42`) {
		t.Errorf("expected uint 42:\n%s", out)
	}
}

func TestCBORDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := cborDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestCBORDecodeHandler_RejectsBadHex(t *testing.T) {
	_, err := cborDecodeHandler(context.Background(), nil, map[string]any{"hex": "ZZ"})
	if err == nil {
		t.Fatal("want error for invalid hex")
	}
}
