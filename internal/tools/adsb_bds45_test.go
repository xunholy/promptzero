package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestADSBBDS45Handler_Golden(t *testing.T) {
	out, err := adsbBDS45DecodeHandler(context.Background(), nil, map[string]any{"mb": "0001FB80000000"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r struct {
		SAT     *float64 `json:"static_air_temperature_c"`
		IsBDS45 bool     `json:"is_bds45"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("bad JSON: %v\n%s", err, out)
	}
	if !r.IsBDS45 || r.SAT == nil || *r.SAT != -4.5 {
		t.Errorf("unexpected decode: %+v (%s)", r, out)
	}
}

func TestADSBBDS45Handler_FullFrame(t *testing.T) {
	out, err := adsbBDS45DecodeHandler(context.Background(), nil, map[string]any{"mb": "A00000000001FB80000000000000"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"static_air_temperature_c": -4.5`) {
		t.Errorf("full-frame extraction failed: %s", out)
	}
}

func TestADSBBDS45Handler_Validation(t *testing.T) {
	if _, err := adsbBDS45DecodeHandler(context.Background(), nil, map[string]any{"mb": ""}); err == nil {
		t.Error("empty mb should error")
	}
	if _, err := adsbBDS45DecodeHandler(context.Background(), nil, map[string]any{"mb": "abcd"}); err == nil {
		t.Error("wrong-length mb should error")
	}
}
