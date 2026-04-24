// Package tools — argument-extraction helpers.
//
// Copied from internal/agent/agent.go (str/intOr/floatOr/boolOr). The
// originals remain in the agent package until Wave 5 cleanup; from Wave 1
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

// intOr extracts an integer from p[key]. Handles float64 (JSON default) and
// string representations. Returns fallback when the key is absent or
// unparseable.
func intOr(p map[string]any, key string, fallback int) int {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case string:
			if i, err := strconv.Atoi(n); err == nil {
				return i
			}
		}
	}
	return fallback
}

// floatOr extracts a float64 from p[key]. Returns fallback when the key is
// absent or the value is not a float64.
// Wave 2+ handlers (subghz_receive duty-cycle, ir_transmit_raw) call this.
//
//nolint:unused
func floatOr(p map[string]any, key string, fallback float64) float64 {
	if v, ok := p[key]; ok {
		if f, ok := v.(float64); ok {
			return f
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
