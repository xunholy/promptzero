package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestADSBBDS44Handler_Golden(t *testing.T) {
	// Accepts the bare 14-hex MB field.
	out, err := adsbBDS44DecodeHandler(context.Background(), nil, map[string]any{"mb": "185BD5CF400000"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r struct {
		FigureOfMerit int     `json:"figure_of_merit"`
		WindSpeedKt   *int    `json:"wind_speed_kt"`
		SAT           float64 `json:"static_air_temperature_c"`
		IsBDS44       bool    `json:"is_bds44"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if !r.IsBDS44 || r.FigureOfMerit != 1 || r.WindSpeedKt == nil || *r.WindSpeedKt != 22 || r.SAT != -48.75 {
		t.Errorf("unexpected decode: %+v (%s)", r, out)
	}
}

func TestADSBBDS44Handler_FullFrame(t *testing.T) {
	// A full 28-hex Comm-B frame (MB is 185BD5CF400000) must extract the MB.
	out, err := adsbBDS44DecodeHandler(context.Background(), nil, map[string]any{"mb": "A0000000185BD5CF400000000000"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"wind_speed_kt": 22`) {
		t.Errorf("full-frame extraction failed: %s", out)
	}
}

func TestADSBBDS44Handler_Validation(t *testing.T) {
	if _, err := adsbBDS44DecodeHandler(context.Background(), nil, map[string]any{"mb": ""}); err == nil {
		t.Error("empty mb should error")
	}
	if _, err := adsbBDS44DecodeHandler(context.Background(), nil, map[string]any{"mb": "1234"}); err == nil {
		t.Error("wrong-length mb should error")
	}
}
