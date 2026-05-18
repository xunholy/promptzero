package tools

import (
	"context"
	"strings"
	"testing"
)

// TestAutomotiveJ1850DecodeHandler_OBDIIRequest confirms the
// Spec handler decodes a typical OBD-II Mode 1 PID 0x0C
// (Engine RPM) request through to JSON.
//
// The CRC byte is computed by the internal/j1850 package; this
// test pins the well-known request bytes 6C F1 10 01 0C and
// includes the expected CRC (computed once and pinned here for
// determinism).
func TestAutomotiveJ1850DecodeHandler_OBDIIRequest(t *testing.T) {
	// CRC for body 6C F1 10 01 0C was computed by Decode in the
	// internal/j1850 test suite.
	out, err := automotiveJ1850DecodeHandler(context.Background(), nil, map[string]any{
		"hex": "6C F1 10 01 0C 0F", // CRC = 0x0F per SAE J1850 CRC-8
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"source_name": "Engine Control Module (ECM)"`) {
		t.Errorf("expected ECM source:\n%s", out)
	}
	if !strings.Contains(out, `"target_name": "Diagnostic Tool / Scan Tool"`) {
		t.Errorf("expected diagnostic tool target:\n%s", out)
	}
	if !strings.Contains(out, `"pid_name": "Engine RPM"`) {
		t.Errorf("expected Engine RPM PID:\n%s", out)
	}
}

func TestAutomotiveJ1850DecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := automotiveJ1850DecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}
