package tools

import (
	"context"
	"strings"
	"testing"
)

// TestZigbeeZCLAttributeDecodeHandler_BooleanTrue confirms the
// Spec handler decodes a boolean attribute through to JSON.
func TestZigbeeZCLAttributeDecodeHandler_BooleanTrue(t *testing.T) {
	out, err := zigbeeZCLAttributeDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "10 01",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"value": true`) {
		t.Errorf("expected value true:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "Boolean"`) {
		t.Errorf("expected Boolean type:\n%s", out)
	}
}

// TestZigbeeZCLAttributeDecodeHandler_CharString confirms
// character-string decoding.
func TestZigbeeZCLAttributeDecodeHandler_CharString(t *testing.T) {
	out, err := zigbeeZCLAttributeDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "42 05 68 65 6C 6C 6F", // "hello"
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"value": "hello"`) {
		t.Errorf("expected value hello:\n%s", out)
	}
}

func TestZigbeeZCLAttributeDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := zigbeeZCLAttributeDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
