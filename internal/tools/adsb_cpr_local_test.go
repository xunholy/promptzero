package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestADSBCPRLocalHandler_Canonical drives the tool with the canonical frame
// and reference position.
func TestADSBCPRLocalHandler_Canonical(t *testing.T) {
	out, err := adsbCPRLocalHandler(context.Background(), nil, map[string]any{
		"frame":   "8D40621D58C382D690C8AC2863A7",
		"ref_lat": 52.258,
		"ref_lon": 3.918,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r struct {
		Latitude  float64 `json:"latitude"`
		Longitude float64 `json:"longitude"`
		Reference string  `json:"reference"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if r.Latitude < 52.256 || r.Latitude > 52.258 || r.Longitude < 3.918 || r.Longitude > 3.921 {
		t.Errorf("position (%.5f, %.5f) outside expected box", r.Latitude, r.Longitude)
	}
	if r.Reference != "local" {
		t.Errorf("reference = %q, want local", r.Reference)
	}
}

// TestADSBCPRLocalHandler_Validation covers the required-arg guards, including
// that ref at 0,0 (equator/prime meridian) is accepted as present.
func TestADSBCPRLocalHandler_Validation(t *testing.T) {
	if _, err := adsbCPRLocalHandler(context.Background(), nil, map[string]any{"frame": "8D40621D58C382D690C8AC2863A7", "ref_lat": 52.0}); err == nil {
		t.Error("missing ref_lon should error")
	}
	// ref 0,0 is a valid present reference (must not be treated as absent).
	if _, err := adsbCPRLocalHandler(context.Background(), nil, map[string]any{
		"frame": "8D40621D58C382D690C8AC2863A7", "ref_lat": 0.0, "ref_lon": 0.0,
	}); err != nil && strings.Contains(err.Error(), "required") {
		t.Errorf("ref 0,0 must count as present, not missing; got %v", err)
	}
}
