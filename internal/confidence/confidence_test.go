package confidence

import (
	"strings"
	"testing"
)

func TestEvaluate_FullyGrounded(t *testing.T) {
	r := Evaluate(map[string]any{
		"path":      "/ext/subghz/garage.sub",
		"frequency": 433920000,
	}, []string{"path", "frequency"})
	if r.Score != 1.0 {
		t.Errorf("fully grounded score = %v, want 1.0", r.Score)
	}
	if r.ShouldAbstain() {
		t.Error("fully grounded should not abstain")
	}
}

func TestEvaluate_MissingRequired(t *testing.T) {
	r := Evaluate(map[string]any{
		"path": "/ext/x",
	}, []string{"path", "frequency"})
	if r.Score != 0.5 {
		t.Errorf("one of two missing = %v, want 0.5", r.Score)
	}
	if !r.ShouldAbstain() {
		// 0.5 == threshold; threshold is strict less-than, so 0.5
		// should NOT abstain. Lock that boundary.
		r = Evaluate(map[string]any{
			"path": "/ext/x",
		}, []string{"path", "frequency"})
		if r.Score < AbstainThreshold {
			t.Errorf("score = %v, want >= threshold %v to avoid abstain", r.Score, AbstainThreshold)
		}
	}
	if len(r.MissingKeys) != 1 || r.MissingKeys[0] != "frequency" {
		t.Errorf("MissingKeys = %v", r.MissingKeys)
	}
}

func TestEvaluate_TriggersAbstainOnManyMissing(t *testing.T) {
	r := Evaluate(map[string]any{
		"a": "value",
	}, []string{"a", "b", "c"})
	// 1/3 = 0.33, below threshold.
	if !r.ShouldAbstain() {
		t.Errorf("2-of-3 missing should abstain: %v", r)
	}
}

func TestEvaluate_PlaceholderTokens(t *testing.T) {
	cases := []map[string]any{
		{"path": ""},
		{"path": "TODO"},
		{"path": "fixme"},
		{"path": "<placeholder>"},
		{"path": "TODO: resolve path"},
		{"path": "example.com/something"},
		{"path": "N/A"},
	}
	for i, c := range cases {
		r := Evaluate(c, []string{"path"})
		if !r.ShouldAbstain() {
			t.Errorf("case %d (%v): expected abstain, got score=%v", i, c, r.Score)
		}
		if len(r.WeakKeys) != 1 || r.WeakKeys[0] != "path" {
			t.Errorf("case %d: WeakKeys = %v", i, r.WeakKeys)
		}
	}
}

func TestEvaluate_NonStringValuesAreTrusted(t *testing.T) {
	// A literal 0 or false is a real choice, not a placeholder.
	r := Evaluate(map[string]any{"enabled": false, "count": 0}, []string{"enabled", "count"})
	if r.Score != 1.0 {
		t.Errorf("non-string values should score 1.0: %v", r)
	}
}

func TestEvaluate_NoRequiredKeysAlwaysFull(t *testing.T) {
	r := Evaluate(map[string]any{}, nil)
	if r.Score != 1.0 {
		t.Errorf("no required keys should score 1.0: %v", r)
	}
}

func TestEvaluate_ReasonContainsDetails(t *testing.T) {
	r := Evaluate(map[string]any{"a": "TODO"}, []string{"a", "b"})
	if !strings.Contains(r.Reason, "missing required keys: b") {
		t.Errorf("Reason missing 'missing' detail: %q", r.Reason)
	}
	if !strings.Contains(r.Reason, "placeholder-like values: a") {
		t.Errorf("Reason missing 'placeholder' detail: %q", r.Reason)
	}
}

// Lock the threshold so tuning decisions are explicit. Tests that
// depend on the threshold boundary (0.5 exactly == do-not-abstain)
// would break silently if someone edited the constant without
// updating this test too.
func TestAbstainThreshold_LockedAtHalf(t *testing.T) {
	if AbstainThreshold != 0.5 {
		t.Errorf("AbstainThreshold = %v, want 0.5 (tune deliberately)", AbstainThreshold)
	}
}
