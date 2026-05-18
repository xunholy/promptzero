package tools

import (
	"context"
	"strings"
	"testing"
)

// TestISO7816ATRDecodeHandler_EMVHappyPath sends a typical EMV
// ATR and confirms the Spec handler decodes it through to JSON
// with the documented top-level shape.
func TestISO7816ATRDecodeHandler_EMVHappyPath(t *testing.T) {
	out, err := iso7816ATRDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "3B 6E 00 00 80 31 80 66 B0 84 0C 01 6E 01 83 00 90 00",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"convention": "direct"`) {
		t.Errorf("expected direct convention in output:\n%s", out)
	}
	if !strings.Contains(out, `"historical_bytes_count": 14`) {
		t.Errorf("expected historical_bytes_count 14 in output:\n%s", out)
	}
}

// TestISO7816ATRDecodeHandler_T1WithTCK confirms the TD chain
// decode picks up the T=1 protocol announcement + valid TCK.
func TestISO7816ATRDecodeHandler_T1WithTCK(t *testing.T) {
	out, err := iso7816ATRDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "3B 80 80 01 01",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"tck_valid": true`) {
		t.Errorf("expected tck_valid true in output:\n%s", out)
	}
}

func TestISO7816ATRDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := iso7816ATRDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
