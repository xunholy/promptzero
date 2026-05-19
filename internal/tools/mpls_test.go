package tools

import (
	"context"
	"strings"
	"testing"
)

// TestMPLSDecodeHandler_SingleLabel_IPv4 pins a canonical
// single-label stack with an IPv4 inner payload.
func TestMPLSDecodeHandler_SingleLabel_IPv4(t *testing.T) {
	in := "00064140 45000028 12340000 40110000 C0A80101 C0A80102"
	out, err := mplsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"label_count": 1`,
		`"label": 100`,
		`"bottom_of_stack": true`,
		`"ttl": 64`,
		`"payload_guess": "IPv4 (first nibble 0x4)"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestMPLSDecodeHandler_TwoLabels pins a 2-label stack.
func TestMPLSDecodeHandler_TwoLabels(t *testing.T) {
	in := "000C8080 0012C140 45000028"
	out, err := mplsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"label_count": 2`) {
		t.Errorf("expected label_count 2:\n%s", out)
	}
}

// TestMPLSDecodeHandler_RouterAlertViolation pins the
// Router-Alert-at-bottom violation detection.
func TestMPLSDecodeHandler_RouterAlertViolation(t *testing.T) {
	in := "00001140 45000028"
	out, err := mplsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "Router Alert") {
		t.Errorf("expected Router Alert violation note:\n%s", out)
	}
}

func TestMPLSDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := mplsDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
