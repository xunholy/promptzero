// subghz_rollback.go — host-side defensive RollBack / rolling-code replay
// detector Spec, delegating to internal/subghz.AnalyzeRollback for the
// sequence-level heuristics.
//
// Wrap-vs-native: native. The reusable part is a deterministic transform
// over caller-supplied, already-decoded rolling-code fields (transmitter
// ID + the transmitted code, optional decrypted counter) — no SDR or
// radio at analysis time. Defensive item from gap-analysis §1.2
// (subghz_rollback_detect, capture-only RollBack detection — attacks #5).

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/subghz"
)

func init() { //nolint:gochecknoinits
	Register(subghzRollbackDetectSpec)
}

var subghzRollbackDetectSpec = Spec{
	Name: "subghz_rollback_detect",
	Description: "Defensive blue-team analysis of a SEQUENCE of captured rolling-code remote " +
		"transmissions (KeeLoq, Security+, and other rolling/hopping-code keyfobs) for the signatures " +
		"of a RollBack / replay attack (Kaiser et al., \"RollBack: A New Time-Agnostic Replay Attack " +
		"Against the Automotive RKE Systems\", DEF CON 2022). Frames are taken in observation order " +
		"(earliest first) and grouped by transmitter ID. Operators feed the already-decoded fields — " +
		"the analyser does no RF work.\n\n" +
		"Two signals, each surfaced as an OBSERVATION with its benign explanation stated — never a " +
		"definitive attack verdict (a confidently-wrong alert is worse than none):\n" +
		" - **replayed_code** (warning, key-free): a rolling code that REappears for a transmitter " +
		"after it had already moved on to a different code. A rolling code is meant to be used exactly " +
		"once, so a non-consecutive duplicate is the core replay signature. CONSECUTIVE identical codes " +
		"are NOT flagged — a remote legitimately retransmits the same code several times per button " +
		"press (a burst), which is collapsed to one logical transmission. Benign explanation: the " +
		"operator's own tooling re-sent a captured .sub, or a duplicated capture.\n" +
		" - **counter_regression** (warning, only when decrypted `counter`s are supplied — i.e. you " +
		"hold the key): a rolling counter lower than the running max for that transmitter. Counters " +
		"increase monotonically by design, so a decrease is a hard invariant violation. Benign " +
		"explanation: frames fed out of capture order, or two remotes cloned to the same serial.\n\n" +
		"No RF / timing / signal-strength heuristic is used — only the caller-supplied, " +
		"deterministically-checkable fields — so it never produces a confidently-wrong reading. " +
		"Companion to subghz_decode (which recovers the id/code) and tpms_anomaly_detect. " +
		"Wrap-vs-native: native — a pure sequence transform, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"frames":{
				"type":"array",
				"description":"Captured rolling-code frames in observation order (earliest first).",
				"items":{
					"type":"object",
					"properties":{
						"id":{"type":"string","description":"Fixed transmitter identity (serial / fixed code) that stays constant across presses. Frames are grouped by it."},
						"code":{"type":"string","description":"The full rolling/hopping code as transmitted (hex or any stable string; separators and a 0x prefix are tolerated). Observable without the manufacturer key."},
						"counter":{"type":"integer","description":"Optional decrypted rolling counter (only if you hold the key); enables the monotonicity check."}
					},
					"required":["id","code"]
				}
			}
		},
		"required":["frames"]
	}`),
	Required:  []string{"frames"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   subghzRollbackDetectHandler,
}

func subghzRollbackDetectHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawFrames, ok := p["frames"].([]any)
	if !ok || len(rawFrames) == 0 {
		return "", fmt.Errorf("subghz_rollback_detect: 'frames' must be a non-empty array of objects")
	}
	frames := make([]subghz.RollbackFrame, 0, len(rawFrames))
	for i, rf := range rawFrames {
		m, ok := rf.(map[string]any)
		if !ok {
			return "", fmt.Errorf("subghz_rollback_detect: frames[%d] is not an object", i)
		}
		f := subghz.RollbackFrame{
			ID:   str(m, "id"),
			Code: str(m, "code"),
		}
		if v, ok := m["counter"].(float64); ok {
			c := int64(v)
			f.Counter = &c
		}
		frames = append(frames, f)
	}

	res, err := subghz.AnalyzeRollback(frames)
	if err != nil {
		return "", fmt.Errorf("subghz_rollback_detect: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
