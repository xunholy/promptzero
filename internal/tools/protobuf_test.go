package tools

import (
	"context"
	"strings"
	"testing"
)

// TestProtobufDecodeHandler_SimpleVarint pins the canonical
// protobuf example: field 1 varint = 150.
func TestProtobufDecodeHandler_SimpleVarint(t *testing.T) {
	out, err := protobufDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "08 96 01",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"field_number": 1`) {
		t.Errorf("expected field_number 1:\n%s", out)
	}
	if !strings.Contains(out, `"wire_type_name": "VARINT"`) {
		t.Errorf("expected wire_type_name VARINT:\n%s", out)
	}
	if !strings.Contains(out, `"uint64": 150`) {
		t.Errorf("expected uint64 150:\n%s", out)
	}
}

func TestProtobufDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := protobufDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestProtobufDecodeHandler_RejectsBadHex(t *testing.T) {
	_, err := protobufDecodeHandler(context.Background(), nil, map[string]any{"hex": "ZZ"})
	if err == nil {
		t.Fatal("want error for invalid hex")
	}
}
