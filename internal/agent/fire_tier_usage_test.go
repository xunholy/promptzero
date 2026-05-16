package agent

import (
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// TestFireTierUsage_PassesModelAndTokenCounts pins the wiring that
// makes per-call tier-routed billing work end-to-end. Pre-v0.196, the
// six tier call sites (reflexion, router, prospective, consensus,
// verify, session-autoname) bypassed the cost callback entirely; v0.196
// adds fireTierUsage as the shared helper that those sites now call.
//
// The contract: when usageCb is non-nil, fireTierUsage forwards the
// model + every Usage field verbatim. When nil, it's a silent no-op
// (every site degrades gracefully when no cost tracker is wired).
func TestFireTierUsage_PassesModelAndTokenCounts(t *testing.T) {
	a := NewForTest("test-model")

	var got Usage
	a.SetUsageCallback(func(u Usage) { got = u })

	a.fireTierUsage("claude-haiku-4-5", anthropic.Usage{
		InputTokens:              1234,
		OutputTokens:             567,
		CacheReadInputTokens:     8901,
		CacheCreationInputTokens: 23,
	})

	if got.Model != "claude-haiku-4-5" {
		t.Errorf("Model = %q; want claude-haiku-4-5", got.Model)
	}
	if got.InputTokens != 1234 {
		t.Errorf("InputTokens = %d; want 1234", got.InputTokens)
	}
	if got.OutputTokens != 567 {
		t.Errorf("OutputTokens = %d; want 567", got.OutputTokens)
	}
	if got.CacheReadTokens != 8901 {
		t.Errorf("CacheReadTokens = %d; want 8901", got.CacheReadTokens)
	}
	if got.CacheCreationTokens != 23 {
		t.Errorf("CacheCreationTokens = %d; want 23", got.CacheCreationTokens)
	}
}

// TestFireTierUsage_NoCallbackIsSilent pins the graceful-degradation
// path: a tier call still fires fireTierUsage even when no cost
// tracker has been wired, and the helper must not panic / call into
// a nil function pointer.
func TestFireTierUsage_NoCallbackIsSilent(t *testing.T) {
	a := NewForTest("test-model")
	// usageCb intentionally nil.
	a.fireTierUsage("claude-opus-4-7", anthropic.Usage{InputTokens: 10})
	// No assertion needed — the contract is "doesn't panic". Test
	// passes by reaching this line.
}

// TestFireTierUsage_DifferentModelsRouteCorrectly verifies that
// successive calls with different models report each model on its
// own Usage event. The cost tracker uses this to bill each tier-call
// at its true rate.
func TestFireTierUsage_DifferentModelsRouteCorrectly(t *testing.T) {
	a := NewForTest("test-model")

	var events []Usage
	a.SetUsageCallback(func(u Usage) { events = append(events, u) })

	a.fireTierUsage("claude-haiku-4-5", anthropic.Usage{InputTokens: 100})
	a.fireTierUsage("claude-sonnet-4-6", anthropic.Usage{InputTokens: 200})
	a.fireTierUsage("claude-opus-4-7", anthropic.Usage{InputTokens: 300})

	if len(events) != 3 {
		t.Fatalf("got %d events; want 3", len(events))
	}
	wantModels := []string{"claude-haiku-4-5", "claude-sonnet-4-6", "claude-opus-4-7"}
	wantTokens := []int64{100, 200, 300}
	for i, e := range events {
		if e.Model != wantModels[i] {
			t.Errorf("event %d: Model = %q; want %q", i, e.Model, wantModels[i])
		}
		if e.InputTokens != wantTokens[i] {
			t.Errorf("event %d: InputTokens = %d; want %d", i, e.InputTokens, wantTokens[i])
		}
	}
}
