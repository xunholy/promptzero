// subghz_jammer.go — host-side defensive sub-GHz jammer detector Spec,
// delegating to internal/subghz.AnalyzeJamming for the RSSI-sequence heuristics.
//
// Wrap-vs-native: native. The reusable part is a deterministic statistical
// transform over a caller-supplied RSSI sample sequence (no SDR/radio at
// analysis time) — the offline complement to the on-device Sub-GHz Jammer
// Detect FAP (loader_subghz_jammer_detect). Defensive item from gap-analysis §3
// rank 16 (subghz_jammer_detect — RSSI floor + dwell heuristic), the sibling of
// subghz_rollback_detect.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/subghz"
)

func init() { //nolint:gochecknoinits
	Register(subghzJammerDetectSpec)
}

var subghzJammerDetectSpec = Spec{
	Name: "subghz_jammer_detect",
	Description: "Defensive blue-team analysis of a captured SEQUENCE of sub-GHz RSSI samples (dBm, in " +
		"capture order) for the signatures of a continuous-carrier / sweep jammer — the **offline, " +
		"host-side complement** to the on-device Sub-GHz Jammer Detect FAP (loader_subghz_jammer_detect), " +
		"which only flags on the Flipper itself. The operator feeds an already-captured RSSI series (e.g. " +
		"from a sub-GHz scan/monitor); the analyser does no RF work.\n\n" +
		"Always reports the objective statistics — min / max / mean / median / std-dev / noise floor " +
		"(a low percentile, robust to bursts) / occupancy fraction / longest continuous dwell — then " +
		"applies the same receive-only \"RSSI floor + dwell\" heuristic as the FAP. Each flag is an " +
		"OBSERVATION with its benign explanation stated, never a jammer verdict (a confidently-wrong " +
		"alert is worse than none):\n" +
		" - **elevated_noise_floor** — the noise floor sits at/above the threshold (a jammer raises the " +
		"level the channel idles at). Benign: a strong nearby legitimate transmitter or a congested band.\n" +
		" - **sustained_occupancy** — most samples are above the busy threshold (continuous rather than " +
		"bursty energy). Benign: a legitimate continuous carrier (analogue video/audio link).\n" +
		" - **long_dwell** — the longest unbroken run above the busy threshold spans most of the capture. " +
		"Benign: same continuous-carrier explanation.\n\n" +
		"The decision thresholds (busy dBm, elevated-floor dBm, floor percentile, occupancy fraction, " +
		"dwell fraction) all have documented defaults, are overridable, and are echoed back in the result " +
		"so the reading is reproducible. No verdict is asserted — the statistics + flags are for an " +
		"operator to correlate. No RF, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 rank 16 (subghz_jammer_detect). Companion to " +
		"subghz_rollback_detect / tpms_anomaly_detect. Wrap-vs-native: native — a pure statistical " +
		"sequence transform, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"samples":{"type":"array","items":{"type":"number"},"description":"RSSI samples in dBm, capture order (earliest first). Typically negative, e.g. -95, -42."},
			"busy_threshold_dbm":{"type":"number","description":"A sample at/above this counts the channel as occupied (default -80)."},
			"elevated_floor_dbm":{"type":"number","description":"A noise floor at/above this flags an elevated floor (default -85)."},
			"floor_percentile":{"type":"number","description":"Percentile used to estimate the noise floor (default 10)."},
			"occupancy_flag":{"type":"number","description":"Occupancy fraction at/above which sustained occupancy is flagged (default 0.85)."},
			"dwell_flag_fraction":{"type":"number","description":"Longest-dwell fraction at/above which a long dwell is flagged (default 0.5)."}
		},
		"required":["samples"]
	}`),
	Required:  []string{"samples"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   subghzJammerDetectHandler,
}

func subghzJammerDetectHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw, ok := p["samples"].([]any)
	if !ok || len(raw) == 0 {
		return "", fmt.Errorf("subghz_jammer_detect: 'samples' must be a non-empty array of numbers (RSSI in dBm)")
	}
	samples := make([]float64, 0, len(raw))
	for i, v := range raw {
		f, ok := v.(float64)
		if !ok {
			return "", fmt.Errorf("subghz_jammer_detect: samples[%d] is not a number", i)
		}
		samples = append(samples, f)
	}
	// 0 selects the documented default in JammingOpts.withDefaults.
	opts := subghz.JammingOpts{
		BusyThresholdDbm:  floatOr(p, "busy_threshold_dbm", 0),
		ElevatedFloorDbm:  floatOr(p, "elevated_floor_dbm", 0),
		FloorPercentile:   floatOr(p, "floor_percentile", 0),
		OccupancyFlag:     floatOr(p, "occupancy_flag", 0),
		DwellFlagFraction: floatOr(p, "dwell_flag_fraction", 0),
	}
	res, err := subghz.AnalyzeJamming(samples, opts)
	if err != nil {
		return "", fmt.Errorf("subghz_jammer_detect: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
