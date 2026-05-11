// Package tools — argument-extraction helpers.
//
// Copied from internal/agent/agent.go (str/intOr/floatOr/boolOr). From Wave 1
// onwards all registry handlers use these copies so the helpers are
// co-located with the Spec definitions rather than across package lines.
package tools

import "strconv"

// str extracts a string from a map[string]any parameter bag.
// Returns "" when the key is absent or the value is not a string.
func str(p map[string]any, key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// intOr extracts an integer from p[key]. Handles every numeric and
// string representation the value might arrive as: float64 (the
// json.Unmarshal default for numbers — primary LLM tool-call path),
// float32, int, int32, int64 (Go-native callers and tests that build
// the param map directly without JSON round-trip), plus string-encoded
// decimals. Returns fallback when the key is absent or the value can't
// be coerced — matches the docstring's "absent or unparseable" promise.
func intOr(p map[string]any, key string, fallback int) int {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case float32:
			return int(n)
		case int:
			return n
		case int32:
			return int(n)
		case int64:
			return int(n)
		case string:
			if i, err := strconv.Atoi(n); err == nil {
				return i
			}
		}
	}
	return fallback
}

// floatOr extracts a float64 from p[key]. Mirrors intOr's accepted set:
// float64 (JSON default) plus int / int32 / int64 / float32 (Go-native
// callers building the param map directly). Returns fallback when the
// key is absent or the value can't be coerced.
// Wave 2+ handlers (subghz_receive duty-cycle, ir_transmit_raw) call this.
//
//nolint:unused
func floatOr(p map[string]any, key string, fallback float64) float64 {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case float64:
			return n
		case float32:
			return float64(n)
		case int:
			return float64(n)
		case int32:
			return float64(n)
		case int64:
			return float64(n)
		}
	}
	return fallback
}

// boolOr extracts a bool from p[key]. Returns fallback when the key is absent
// or the value is not a bool.
func boolOr(p map[string]any, key string, fallback bool) bool {
	if v, ok := p[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return fallback
}
