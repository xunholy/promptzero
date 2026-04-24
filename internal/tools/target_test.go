package tools

import (
	"context"
	"testing"
)

// targetSpecsCached holds target_* specs captured in init() — before any test
// function (including spec_test.go's resetForTest() calls) can clear the registry.
var (
	targetRememberSpecCached Spec
	targetRecallSpecCached   Spec
	targetForgetSpecCached   Spec
)

func init() {
	// init() runs after the package's own init() functions (which register
	// the specs) but before any test function. This lets us capture spec
	// references that remain valid even after spec_test.go calls resetForTest().
	targetRememberSpecCached, _ = Get("target_remember")
	targetRecallSpecCached, _ = Get("target_recall")
	targetForgetSpecCached, _ = Get("target_forget")
}

// TestTargetToolsNilTolerance verifies that target_remember, target_recall,
// and target_forget return an error (not a panic) when Deps.TargetMem is nil.
func TestTargetToolsNilTolerance(t *testing.T) {
	ctx := context.Background()
	nilDeps := &Deps{} // TargetMem is nil

	cases := []struct {
		name   string
		spec   Spec
		params map[string]any
	}{
		{"target_remember", targetRememberSpecCached, map[string]any{"identifier": "AA:BB:CC"}},
		{"target_recall", targetRecallSpecCached, map[string]any{}},
		{"target_forget", targetForgetSpecCached, map[string]any{"identifier": "AA:BB:CC"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.spec.Name == "" {
				t.Fatalf("spec for %q not captured at init time — check registration", tc.name)
			}
			_, err := tc.spec.Handler(ctx, nilDeps, tc.params)
			if err == nil {
				t.Fatalf("%s with nil TargetMem should return an error, got nil", tc.name)
			}
		})
	}
}

// TestTargetToolsAgentOnly ensures target_* specs are marked AgentOnly.
func TestTargetToolsAgentOnly(t *testing.T) {
	for _, spec := range []Spec{targetRememberSpecCached, targetRecallSpecCached, targetForgetSpecCached} {
		if spec.Name == "" {
			t.Fatalf("spec not captured at init time")
		}
		if !spec.AgentOnly {
			t.Errorf("%s.AgentOnly = false, want true", spec.Name)
		}
	}
}
