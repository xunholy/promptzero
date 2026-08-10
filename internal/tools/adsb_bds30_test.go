package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestADSBBDS30Handler_ThreatICAO(t *testing.T) {
	out, err := adsbBDS30DecodeHandler(context.Background(), nil, map[string]any{"mb": "30E0000686CB0C"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r struct {
		ThreatICAO string `json:"threat_icao"`
		IsBDS30    bool   `json:"is_bds30"`
		RA         struct {
			Issued        bool `json:"issued"`
			DownwardSense bool `json:"downward_sense"`
		} `json:"resolution_advisory"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if !r.IsBDS30 || r.ThreatICAO != "A1B2C3" || !r.RA.Issued || !r.RA.DownwardSense {
		t.Errorf("unexpected decode: %+v (%s)", r, out)
	}
}

func TestADSBBDS30Handler_FullFrame(t *testing.T) {
	out, err := adsbBDS30DecodeHandler(context.Background(), nil, map[string]any{"mb": "A000000030E0000686CB0C000000"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"threat_icao": "A1B2C3"`) {
		t.Errorf("full-frame extraction failed: %s", out)
	}
}

func TestADSBBDS30Handler_Validation(t *testing.T) {
	if _, err := adsbBDS30DecodeHandler(context.Background(), nil, map[string]any{"mb": ""}); err == nil {
		t.Error("empty mb should error")
	}
	if _, err := adsbBDS30DecodeHandler(context.Background(), nil, map[string]any{"mb": "xyz"}); err == nil {
		t.Error("bad mb should error")
	}
}
