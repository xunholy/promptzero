package tools

import (
	"context"
	"strings"
	"testing"
)

// TestZigbeeZCLDecodeHandler_ReadAttributesHappyPath confirms
// the Spec handler decodes a Read Attributes command through
// to JSON.
func TestZigbeeZCLDecodeHandler_ReadAttributesHappyPath(t *testing.T) {
	out, err := zigbeeZCLDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "00 42 00 04 00 05 00",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"command_name": "Read Attributes"`) {
		t.Errorf("expected Read Attributes:\n%s", out)
	}
	if !strings.Contains(out, `"frame_type_name": "Profile-wide"`) {
		t.Errorf("expected Profile-wide:\n%s", out)
	}
}

// TestZigbeeZCLDecodeHandler_ManufacturerSpecific confirms the
// 2-byte manufacturer code is surfaced when the flag is set.
func TestZigbeeZCLDecodeHandler_ManufacturerSpecific(t *testing.T) {
	out, err := zigbeeZCLDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "05 7C 11 01 00 AA BB",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"manufacturer_code": "117C"`) {
		t.Errorf("expected manufacturer_code 117C:\n%s", out)
	}
}

func TestZigbeeZCLDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := zigbeeZCLDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
