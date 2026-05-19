package tools

import (
	"context"
	"strings"
	"testing"
)

// TestBacnetIPDecodeHandler_WhoIs pins a Who-Is broadcast
// through the Spec handler.
func TestBacnetIPDecodeHandler_WhoIs(t *testing.T) {
	out, err := bacnetIPDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "81 0B 00 0C 01 20 FF FF 00 FF 10 08",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"function_name": "Original-Broadcast-NPDU"`) {
		t.Errorf("expected BVLC function name:\n%s", out)
	}
	if !strings.Contains(out, `"service_choice_name": "who-Is"`) {
		t.Errorf("expected who-Is service choice:\n%s", out)
	}
	if !strings.Contains(out, `"pdu_type_name": "Unconfirmed-Request-PDU"`) {
		t.Errorf("expected Unconfirmed-Request PDU type:\n%s", out)
	}
}

func TestBacnetIPDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := bacnetIPDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestBacnetIPDecodeHandler_RejectsBadLength(t *testing.T) {
	_, err := bacnetIPDecodeHandler(context.Background(), nil, map[string]any{"hex": "81 0B"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
