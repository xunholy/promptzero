package tools

import (
	"context"
	"strings"
	"testing"
)

// TestBFDControlDecodeHandler_UpSession pins a canonical
// BFD Up-state session through the Spec handler.
func TestBFDControlDecodeHandler_UpSession(t *testing.T) {
	in := "20 C0 03 18 00000001 00000002 000F4240 000F4240 00000000"
	out, err := bfdControlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	for _, want := range []string{
		`"state_name": "Up"`,
		`"diagnostic_name": "No Diagnostic"`,
		`"detect_multiplier": 3`,
		`"my_discriminator_hex": "0x00000001"`,
		`"desired_min_tx_interval_ms": 1000`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("expected %q in output:\n%s", want, out)
		}
	}
}

// TestBFDControlDecodeHandler_DownPathDown pins a Down state
// with Path Down diagnostic.
func TestBFDControlDecodeHandler_DownPathDown(t *testing.T) {
	in := "25 40 03 18 00000001 00000000 000F4240 000F4240 00000000"
	out, err := bfdControlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"state_name": "Down"`) {
		t.Errorf("expected Down state:\n%s", out)
	}
	if !strings.Contains(out, `"diagnostic_name": "Path Down"`) {
		t.Errorf("expected Path Down diag:\n%s", out)
	}
}

// TestBFDControlDecodeHandler_WithSimplePasswordAuth pins
// the auth-section decoding.
func TestBFDControlDecodeHandler_WithSimplePasswordAuth(t *testing.T) {
	in := "20 C4 03 23 00000001 00000002 000F4240 000F4240 00000000" +
		"01 0B 01 70617373776F7264"
	out, err := bfdControlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": in})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"flag_authentication_present": true`) {
		t.Errorf("expected auth flag true:\n%s", out)
	}
	if !strings.Contains(out, `"type_name": "Simple Password"`) {
		t.Errorf("expected Simple Password auth:\n%s", out)
	}
	if !strings.Contains(out, `"password_text": "password"`) {
		t.Errorf("expected decoded password:\n%s", out)
	}
}

func TestBFDControlDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := bfdControlDecodeHandler(context.Background(), nil,
		map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
