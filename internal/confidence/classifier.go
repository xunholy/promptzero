package confidence

import (
	"encoding/json"
	"strings"
)

// ClassifierKind names a classifier surface that can carry a
// confidence signal. Strings are stable so they round-trip through
// the persona YAML's `confidence:` map without translation.
type ClassifierKind string

const (
	// KindVision is the analyze_image / vision-tool classifier.
	KindVision ClassifierKind = "vision"

	// KindRouter is the per-turn tool-group router (see
	// internal/agent/router.go). Below-threshold confidence routes
	// to the full-catalog fallback rather than acting on a guess.
	KindRouter ClassifierKind = "router"
)

// DefaultClassifierThreshold is used when a persona doesn't override
// a per-classifier threshold. 0.5 is the historical default applied
// to the input-grounding [AbstainThreshold] sibling and reuses the
// same operator intuition: "anything south of 50 % is a guess; ask".
const DefaultClassifierThreshold Score = 0.5

// ParseClassifierResponse extracts a confidence score from an LLM
// classifier response. The model may return any of:
//
//   - a JSON object with a top-level `confidence` field, e.g.
//     `{"groups":[...],"confidence":0.82}` or `{"answer":"…","confidence":0.4}`.
//   - a JSON array (the older router shape) — no confidence signal,
//     returns ok=false and confidence=1.0 (treat as "model did not
//     opt in to abstention; act on the response").
//   - free-text prose — no JSON parse, ok=false, confidence=1.0.
//
// Returns (confidence, ok). The bool reports whether the response
// actually carried a confidence field; a false ok is the contract
// for "no signal" — the caller should NOT treat that as low
// confidence, because doing so would penalise the historical
// no-confidence callers and effectively force abstention everywhere
// during a roll-out.
//
// Score is clamped to [0, 1] regardless of what the model emits, so
// a malicious or buggy classifier can't push the agent into either
// always-abstain (negative) or never-abstain (>1) territory.
func ParseClassifierResponse(text string) (Score, bool) {
	text = strings.TrimSpace(text)
	if text == "" {
		return Score(1.0), false
	}
	// Object form: {"…":…, "confidence":0.x}
	if strings.HasPrefix(text, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(text), &obj); err == nil {
			if raw, ok := obj["confidence"]; ok {
				if f, ok := toFloat(raw); ok {
					return clampScore(f), true
				}
			}
		}
	}
	return Score(1.0), false
}

// ShouldAbstainAt is the per-classifier abstention check. A nil or
// zero threshold falls back to [DefaultClassifierThreshold]. Returns
// true when score is strictly less than the resolved threshold.
//
// Used by the agent at vision and router call sites to decide whether
// to act on the classifier output or route to a clarifying user
// question (vision) / full-catalog fallback (router).
func ShouldAbstainAt(score Score, threshold Score) bool {
	if threshold <= 0 {
		threshold = DefaultClassifierThreshold
	}
	return score < threshold
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		// Some models emit confidence as a quoted decimal: "0.82".
		// Be tolerant.
		var f float64
		_, err := jsonNumber(n, &f)
		return f, err == nil
	}
	return 0, false
}

// jsonNumber decodes s as a JSON number into *out. Wrapper around
// json.Unmarshal so the toFloat string branch handles quoted
// decimals consistently with how the JSON parser would have read
// them inside an object.
func jsonNumber(s string, out *float64) (int, error) {
	return len(s), json.Unmarshal([]byte(s), out)
}

func clampScore(f float64) Score {
	if f < 0 {
		return 0
	}
	if f > 1 {
		return 1
	}
	return Score(f)
}
