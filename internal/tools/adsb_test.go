package tools

import (
	"context"
	"strings"
	"testing"
)

// TestADSBModeSDecodeHandler_KLM1023 pins the MIT-textbook
// Aircraft Identification frame through the Spec handler to
// JSON.
func TestADSBModeSDecodeHandler_KLM1023(t *testing.T) {
	out, err := adsbModeSDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "8D4840D6202CC371C32CE0576098",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"df": 17`) {
		t.Errorf("expected df 17:\n%s", out)
	}
	if !strings.Contains(out, `"icao_address": "4840D6"`) {
		t.Errorf("expected ICAO 4840D6:\n%s", out)
	}
	if !strings.Contains(out, `"callsign": "KLM1023"`) {
		t.Errorf("expected KLM1023 callsign:\n%s", out)
	}
	if !strings.Contains(out, `"crc_valid": true`) {
		t.Errorf("expected crc_valid true:\n%s", out)
	}
}

func TestADSBModeSDecodeHandler_RejectsEmpty(t *testing.T) {
	_, err := adsbModeSDecodeHandler(context.Background(), nil, map[string]any{"hex": ""})
	if err == nil {
		t.Fatal("want error for empty hex")
	}
}

func TestADSBModeSDecodeHandler_RejectsBadLength(t *testing.T) {
	_, err := adsbModeSDecodeHandler(context.Background(), nil, map[string]any{"hex": "8D48"})
	if err == nil {
		t.Fatal("want error for short hex")
	}
}
