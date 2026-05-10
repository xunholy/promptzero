package tools

import "testing"

// args_test.go pins the four parameter-bag extractors every tool
// Handler in the registry calls. The JSON-payload shape coming in
// from the Anthropic API is map[string]any{}; types are float64
// (numbers), string, bool. These helpers normalise that into typed
// Go values with safe fallbacks, so a regression here silently
// breaks every tool handler that consumes typed inputs.

// TestStr pins string extraction. Missing key → "", wrong type
// (number / bool) → "", correct type returns the value.
func TestStr(t *testing.T) {
	p := map[string]any{
		"good":   "hello",
		"empty":  "",
		"number": float64(42),
		"bool":   true,
		"nil":    nil,
	}
	if got := str(p, "good"); got != "hello" {
		t.Errorf("str(good) = %q, want hello", got)
	}
	if got := str(p, "empty"); got != "" {
		t.Errorf("str(empty) = %q, want \"\"", got)
	}
	if got := str(p, "number"); got != "" {
		t.Errorf("str(number) = %q, want \"\" (wrong-type fallback)", got)
	}
	if got := str(p, "bool"); got != "" {
		t.Errorf("str(bool) = %q, want \"\"", got)
	}
	if got := str(p, "nil"); got != "" {
		t.Errorf("str(nil) = %q, want \"\"", got)
	}
	if got := str(p, "missing"); got != "" {
		t.Errorf("str(missing) = %q, want \"\"", got)
	}
}

// TestIntOr pins int extraction. The JSON decoder gives us
// float64 by default, but tool inputs sometimes arrive as strings
// (e.g. when a CLI flag stringifies a number) — both paths must
// parse. Missing key / unparseable / wrong-type → fallback.
func TestIntOr(t *testing.T) {
	p := map[string]any{
		"int_as_float":   float64(42),
		"int_zero":       float64(0),
		"int_negative":   float64(-7),
		"float_truncate": float64(3.9), // int conversion truncates → 3
		"str_int":        "100",
		"str_negative":   "-50",
		"str_invalid":    "not-a-number",
		"bool":           true,
		"nil":            nil,
	}
	tests := []struct {
		key      string
		fallback int
		want     int
	}{
		{"int_as_float", -1, 42},
		{"int_zero", -1, 0},
		{"int_negative", -1, -7},
		{"float_truncate", -1, 3},
		{"str_int", -1, 100},
		{"str_negative", -1, -50},
		{"str_invalid", 99, 99},
		{"bool", 99, 99},
		{"nil", 99, 99},
		{"missing", 99, 99},
	}
	for _, tc := range tests {
		if got := intOr(p, tc.key, tc.fallback); got != tc.want {
			t.Errorf("intOr(%s, %d) = %d, want %d", tc.key, tc.fallback, got, tc.want)
		}
	}
}

// TestFloatOr pins float64 extraction. JSON-default numeric type.
// Wave 2+ handlers (ir_transmit_raw duty-cycle, etc.) consume
// fractional values so the wrong-type fallback path matters.
func TestFloatOr(t *testing.T) {
	p := map[string]any{
		"good":     float64(3.14),
		"zero":     float64(0),
		"negative": float64(-2.5),
		"str":      "0.5", // string is NOT accepted (use intOr if numeric-as-string is wanted)
		"int_like": float64(1.0),
	}
	tests := []struct {
		key      string
		fallback float64
		want     float64
	}{
		{"good", -1, 3.14},
		{"zero", -1, 0},
		{"negative", -1, -2.5},
		{"int_like", -1, 1.0},
		{"str", -1, -1}, // string fallback (floatOr only accepts float64)
		{"missing", 7.7, 7.7},
	}
	for _, tc := range tests {
		if got := floatOr(p, tc.key, tc.fallback); got != tc.want {
			t.Errorf("floatOr(%s, %v) = %v, want %v", tc.key, tc.fallback, got, tc.want)
		}
	}
}

// TestBoolOr pins bool extraction. Number / string truthy values
// are NOT coerced — bool is strict, fallback otherwise.
func TestBoolOr(t *testing.T) {
	p := map[string]any{
		"true_val":  true,
		"false_val": false,
		"str_true":  "true",     // strings NOT coerced
		"int_one":   float64(1), // numbers NOT coerced
		"nil":       nil,
	}
	tests := []struct {
		key      string
		fallback bool
		want     bool
	}{
		{"true_val", false, true},
		{"false_val", true, false},
		{"str_true", false, false}, // string → fallback
		{"int_one", false, false},  // number → fallback
		{"nil", true, true},
		{"missing", true, true},
		{"missing", false, false},
	}
	for _, tc := range tests {
		if got := boolOr(p, tc.key, tc.fallback); got != tc.want {
			t.Errorf("boolOr(%s, %v) = %v, want %v", tc.key, tc.fallback, got, tc.want)
		}
	}
}
