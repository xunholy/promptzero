package tools

import (
	"context"
	"strings"
	"testing"
)

// TestZigbeeAPSDecodeHandler_DataHappyPath sends a typical
// Home Automation data frame and confirms the Spec handler
// decodes it through to JSON.
func TestZigbeeAPSDecodeHandler_DataHappyPath(t *testing.T) {
	out, err := zigbeeAPSDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "40 01 06 00 04 01 01 AB 01 00 02",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"frame_type_name": "Data"`) {
		t.Errorf("expected Data frame type:\n%s", out)
	}
	if !strings.Contains(out, `"cluster_id": "0006"`) {
		t.Errorf("expected On/Off cluster 0006:\n%s", out)
	}
	if !strings.Contains(out, `"profile_name": "Home Automation (HA)"`) {
		t.Errorf("expected HA profile:\n%s", out)
	}
}

// TestZigbeeAPSDecodeHandler_GroupDelivery confirms group
// delivery surfaces the group address instead of dest endpoint.
func TestZigbeeAPSDecodeHandler_GroupDelivery(t *testing.T) {
	out, err := zigbeeAPSDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "4C 34 12 06 00 04 01 05 01",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"group_address": "1234"`) {
		t.Errorf("expected group_address 1234:\n%s", out)
	}
	if !strings.Contains(out, `"delivery_mode_name": "Group"`) {
		t.Errorf("expected Group delivery:\n%s", out)
	}
}

func TestZigbeeAPSDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := zigbeeAPSDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
