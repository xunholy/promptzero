package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestADSBCPRDecodeHandler_Canonical drives the tool with the canonical
// even/odd frame pair and checks the resolved coordinate.
func TestADSBCPRDecodeHandler_Canonical(t *testing.T) {
	out, err := adsbCPRDecodeHandler(context.Background(), nil, map[string]any{
		"even_frame": "8D40621D58C382D690C8AC2863A7",
		"odd_frame":  "8D40621D58C386435CC412692AD6",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r struct {
		ICAOAddress string  `json:"icao_address"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		Reference   string  `json:"reference"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if r.Latitude < 52.256 || r.Latitude > 52.258 || r.Longitude < 3.918 || r.Longitude > 3.921 {
		t.Errorf("position (%.5f, %.5f) outside expected box around (52.2572, 3.91937)", r.Latitude, r.Longitude)
	}
	if r.ICAOAddress != "40621D" {
		t.Errorf("ICAO = %q, want 40621D", r.ICAOAddress)
	}
}

// TestADSBCPRDecodeHandler_Validation covers the required-arg and enum guards.
func TestADSBCPRDecodeHandler_Validation(t *testing.T) {
	if _, err := adsbCPRDecodeHandler(context.Background(), nil, map[string]any{"even_frame": "8D40621D58C382D690C8AC2863A7"}); err == nil {
		t.Error("missing odd_frame should error")
	}
	_, err := adsbCPRDecodeHandler(context.Background(), nil, map[string]any{
		"even_frame": "8D40621D58C382D690C8AC2863A7",
		"odd_frame":  "8D40621D58C386435CC412692AD6",
		"recent":     "sideways",
	})
	if err == nil || !strings.Contains(err.Error(), "recent") {
		t.Errorf("bad 'recent' value should error naming the field; got %v", err)
	}
}
