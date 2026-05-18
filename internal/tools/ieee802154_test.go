package tools

import (
	"context"
	"strings"
	"testing"
)

// TestIEEE802154DecodeHandler_AckHappyPath sends a minimum Ack
// frame and confirms the Spec handler returns JSON with
// frame_type_name set.
func TestIEEE802154DecodeHandler_AckHappyPath(t *testing.T) {
	out, err := ieee802154DecodeHandler(context.Background(), nil, map[string]any{
		"hex": "02 00 7B",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"frame_type_name": "Acknowledgment"`) {
		t.Errorf("expected Acknowledgment in output:\n%s", out)
	}
}

// TestIEEE802154DecodeHandler_DataFrameWithFCS exercises the
// include_fcs option flag.
func TestIEEE802154DecodeHandler_DataFrameWithFCS(t *testing.T) {
	out, err := ieee802154DecodeHandler(context.Background(), nil, map[string]any{
		"hex":         "41 88 42 FE CA BE BA AD DE DEADBEEF AB CD",
		"include_fcs": true,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"fcs_hex": "ABCD"`) {
		t.Errorf("expected fcs_hex ABCD in output:\n%s", out)
	}
	if !strings.Contains(out, `"fcs_included": true`) {
		t.Errorf("expected fcs_included true in output:\n%s", out)
	}
}

func TestIEEE802154DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := ieee802154DecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
