// tpms_anomaly.go — host-side defensive TPMS anomaly detector Spec,
// delegating to internal/tpms for per-frame decode + the sequence-level
// anomaly heuristics.
//
// Wrap-vs-native: native. The reusable part is a deterministic transform
// over the decoded sensor IDs + CRC validity the tpms package already
// produces — no SDR or vehicle at analysis time. Defensive sibling of
// subghz_tpms_decode (gap-analysis §3 rank 6).

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tpms"
)

func init() { //nolint:gochecknoinits
	Register(tpmsAnomalyDecodeSpec)
}

var tpmsAnomalyDecodeSpec = Spec{
	Name: "tpms_anomaly_detect",
	Description: "Defensive blue-team analysis of a SEQUENCE of TPMS Sub-GHz frames — the same " +
		"pre-demodulated '0'/'1' Manchester bit-streams subghz_tpms_decode takes, one per array " +
		"element. Decodes each frame (sensor ID + CRC-8 validity) and reports deterministic anomaly " +
		"signals over the set, for monitoring a target vehicle for TPMS sensor-ID spoofing/injection " +
		"(the TPMS attack class — inject extra sensor IDs to trigger dashboard warnings or to track a " +
		"vehicle by emitting a known ID).\n\n" +
		"Two signals, each surfaced as an OBSERVATION with its benign explanation stated — never a " +
		"definitive attack verdict (a confidently-wrong alert is worse than none):\n" +
		" - **excess_sensors** (warning): more unique 32-bit sensor IDs than the vehicle's wheel count " +
		"(`expected_sensors`, default 4). Consistent with sensor-ID injection/spoofing OR simply more " +
		"than one vehicle in radio range — correlate with location/time.\n" +
		" - **crc_invalid** (info): frames matching no covered CRC-8 polynomial (0x07/0x2F/0x13). " +
		"Consistent with a crafted/injected frame OR a TPMS family whose CRC poly isn't covered.\n\n" +
		"Pressure/temperature anomaly detection is deliberately absent — the field layouts are per-" +
		"family and unverifiable offline (see subghz_tpms_decode), so flagging on them would risk the " +
		"confidently-wrong reading this family refuses to produce.\n\n" +
		"Pure offline analyser — no SDR or vehicle at analysis time. Companion to subghz_tpms_decode; " +
		"source: docs/catalog/gap-analysis.md §3 rank 6 (tpms_anomaly_detect).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"frames":{"type":"array","items":{"type":"string"},"description":"TPMS Manchester bit-streams ('0'/'1', separators tolerated), one per element — the same input subghz_tpms_decode takes."},
			"expected_sensors":{"type":"integer","description":"The target vehicle's direct-TPMS wheel count (default 4). More unique sensor IDs than this raises excess_sensors."}
		},
		"required":["frames"]
	}`),
	Required:  []string{"frames"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   tpmsAnomalyDecodeHandler,
}

func tpmsAnomalyDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawFrames, ok := p["frames"].([]any)
	if !ok || len(rawFrames) == 0 {
		return "", fmt.Errorf("tpms_anomaly_detect: 'frames' must be a non-empty array of bit-streams")
	}
	frames := make([]string, 0, len(rawFrames))
	for i, rf := range rawFrames {
		s, ok := rf.(string)
		if !ok {
			return "", fmt.Errorf("tpms_anomaly_detect: frames[%d] is not a string", i)
		}
		frames = append(frames, s)
	}

	expected := 0 // 0 → package default (4)
	if v, ok := p["expected_sensors"].(float64); ok {
		expected = int(v)
	}

	res, err := tpms.AnalyzeFrames(frames, expected)
	if err != nil {
		return "", fmt.Errorf("tpms_anomaly_detect: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
