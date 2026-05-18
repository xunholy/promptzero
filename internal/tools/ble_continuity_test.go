package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestBLEContinuityDecodeHandler_HappyPathProducesJSON pins that the
// Spec handler wraps the underlying ble.Decode call and returns
// valid JSON with the documented top-level shape.
func TestBLEContinuityDecodeHandler_HappyPathProducesJSON(t *testing.T) {
	out, err := bleContinuityDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "10051B18AABBCC",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var decoded struct {
		TLVs []struct {
			Type    int            `json:"type"`
			TypeHex string         `json:"type_hex"`
			Name    string         `json:"name"`
			Length  int            `json:"length"`
			Hex     string         `json:"hex"`
			Fields  map[string]any `json:"fields"`
		} `json:"tlvs"`
		Count          int    `json:"count"`
		StrippedPrefix string `json:"stripped_prefix"`
	}
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("output not valid JSON: %v\n%s", err, out)
	}
	if decoded.Count != 1 {
		t.Fatalf("Count = %d; want 1\n%s", decoded.Count, out)
	}
	if decoded.TLVs[0].Name != "NearbyInfo" {
		t.Errorf("Name = %q; want 'NearbyInfo'", decoded.TLVs[0].Name)
	}
	if decoded.TLVs[0].TypeHex != "10" {
		t.Errorf("TypeHex = %q; want '10'", decoded.TLVs[0].TypeHex)
	}
}

func TestBLEContinuityDecodeHandler_RejectsEmpty(t *testing.T) {
	for _, in := range []string{"", "   "} {
		_, err := bleContinuityDecodeHandler(context.Background(), nil, map[string]any{"hex": in})
		if err == nil {
			t.Errorf("handler(hex=%q) = nil; want 'hex is required' error", in)
		}
		if err != nil && !strings.Contains(err.Error(), "hex") {
			t.Errorf("err = %v; want mention of hex field", err)
		}
	}
}

// TestBLEContinuityDecodeHandler_PrefixAutoStrip confirms the
// manufacturer-prefix and AD-structure prefix detectors survive the
// JSON round-trip (the StrippedPrefix field exists for operators to
// confirm the parser interpreted the input as expected).
func TestBLEContinuityDecodeHandler_PrefixAutoStrip(t *testing.T) {
	out, err := bleContinuityDecodeHandler(context.Background(), nil, map[string]any{
		"hex": "4C0010051B00AABBCC",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"stripped_prefix": "manufacturer"`) {
		t.Errorf("expected stripped_prefix=manufacturer in JSON:\n%s", out)
	}
}
