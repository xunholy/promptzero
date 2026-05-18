package tools

import (
	"context"
	"strings"
	"testing"
)

// TestZigbeeNWKDecodeHandler_DataFrameHappyPath sends a minimal
// data frame and confirms the Spec handler decodes it through
// to JSON.
func TestZigbeeNWKDecodeHandler_DataFrameHappyPath(t *testing.T) {
	out, err := zigbeeNWKDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "08 00 00 00 34 12 1E 01 AA BB CC",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"frame_type_name": "Data"`) {
		t.Errorf("expected Data frame type in output:\n%s", out)
	}
	if !strings.Contains(out, `"source_address": "1234"`) {
		t.Errorf("expected source 1234:\n%s", out)
	}
	if !strings.Contains(out, `"payload_hex": "AABBCC"`) {
		t.Errorf("expected payload AABBCC:\n%s", out)
	}
}

// TestZigbeeNWKDecodeHandler_BroadcastFrame confirms the
// broadcast-class identification for the all-non-sleepy
// address.
func TestZigbeeNWKDecodeHandler_BroadcastFrame(t *testing.T) {
	out, err := zigbeeNWKDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "08 00 FD FF 34 12 1E 01",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"broadcast_class": "All non-sleepy nodes"`) {
		t.Errorf("expected broadcast class in output:\n%s", out)
	}
}

func TestZigbeeNWKDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := zigbeeNWKDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
