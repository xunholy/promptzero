// SPDX-License-Identifier: AGPL-3.0-or-later

// subghz_classify.go — pure-Go Sub-GHz protocol classifier Spec.
//
// Runs internal/subghz.Classifier against a Flipper .sub capture file
// (or base64-encoded data) and returns the top-N matched protocols with
// decoded payloads. No Docker required — this is the fast pure-Go path.
// urh_decode_sub (Docker/urh-ng bridge) remains the fallback for exotic
// protocols not covered by the 20 built-in decoders.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/subghz"
)

func init() { //nolint:gochecknoinits
	Register(subghzClassifySpec)
}

var subghzClassifySpec = Spec{
	Name: "subghz_classify",
	Description: "Classify a Flipper .sub capture file against the 28 most common Sub-GHz protocols " +
		"(Princeton PT2262, CAME, Holtek HT12E, Linear, NICE FloR-S, KeeLoq HCS, FAAC SLH, Beninca, " +
		"Prastel, Ansonic, Smartgate, Aerolite, Doitrand, Security+ v1, Magicode, Honeywell WS, " +
		"Princeton-Holtek, CAME TWIN, Aprimatic, Phoenix V2, NICE FLO, BFT Mitto, Somfy RTS, Marantec, " +
		"BETT, Security+ v2, Gate TX, SMC5326). Returns top-N matches with confidence " +
		"scores and decoded payloads (address, serial, button, rolling code, etc.). " +
		"Pure Go — no Docker required. Use urh_decode_sub as fallback for unmatched captures.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"sub_path":{"type":"string",
				"description":"Local filesystem path to a Flipper .sub file. Mutually exclusive with sub_data_b64."},
			"sub_data_b64":{"type":"string",
				"description":"Base64-encoded .sub file bytes. Mutually exclusive with sub_path."},
			"top_n":{"type":"integer","minimum":1,"maximum":20,
				"description":"Number of top matches to return (default 3)."}
		}
	}`),
	Required:  nil,
	Risk:      risk.Low,
	Group:     GroupFlipperSubGHz,
	AgentOnly: false,
	Handler:   subghzClassifyHandler,
}

func subghzClassifyHandler(_ context.Context, _ *Deps, args map[string]any) (string, error) {
	var subBytes []byte

	if p := str(args, "sub_path"); p != "" {
		b, err := os.ReadFile(p) //nolint:gosec // operator-supplied path; risk gate already passed
		if err != nil {
			return "", fmt.Errorf("subghz_classify: read %s: %w", p, err)
		}
		subBytes = b
	} else if d := str(args, "sub_data_b64"); d != "" {
		b, err := base64.StdEncoding.DecodeString(d)
		if err != nil {
			return "", fmt.Errorf("subghz_classify: decode sub_data_b64: %w", err)
		}
		subBytes = b
	} else {
		return "", fmt.Errorf("subghz_classify: provide sub_path or sub_data_b64")
	}

	topN := intOr(args, "top_n", 3)

	sf, err := subghz.Parse(strings.NewReader(string(subBytes)))
	if err != nil {
		return "", fmt.Errorf("subghz_classify: parse .sub: %w", err)
	}
	if len(sf.Pulses) == 0 {
		out := map[string]any{
			"matched":   false,
			"reason":    "no pulse data in capture",
			"frequency": sf.Frequency,
			"preset":    sf.Preset,
		}
		b, _ := json.Marshal(out)
		return string(b), nil
	}

	c := subghz.NewClassifier()
	matches := c.Classify(sf.Pulses, topN)

	type matchJSON struct {
		Protocol   string         `json:"protocol"`
		Confidence float64        `json:"confidence"`
		BitCount   int            `json:"bit_count"`
		Payload    map[string]any `json:"payload"`
	}
	results := make([]matchJSON, 0, len(matches))
	for _, m := range matches {
		results = append(results, matchJSON{
			Protocol:   m.Protocol,
			Confidence: m.Confidence,
			BitCount:   len(m.Bits),
			Payload:    m.Payload,
		})
	}

	out := map[string]any{
		"matched":     len(results) > 0,
		"top_n":       topN,
		"frequency":   sf.Frequency,
		"preset":      sf.Preset,
		"pulse_count": len(sf.Pulses),
		"matches":     results,
	}
	if len(results) == 0 {
		out["hint"] = "no built-in protocol matched — try urh_decode_sub for exotic protocols"
	}

	b, _ := json.Marshal(out)
	return string(b), nil
}
