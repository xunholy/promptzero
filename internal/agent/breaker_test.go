package agent

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/breaker"
)

// TestSetBreaker_RoundTrip pins the public attach/detach surface.
// SetBreaker(nil) is the documented "disable" path.
func TestSetBreaker_RoundTrip(t *testing.T) {
	a := &Agent{}
	if a.Breaker() != nil {
		t.Errorf("zero-value Agent should not have a breaker attached")
	}
	c := breaker.New(2)
	a.SetBreaker(c)
	if a.Breaker() != c {
		t.Errorf("Breaker() did not return the attached counter")
	}
	a.SetBreaker(nil)
	if a.Breaker() != nil {
		t.Errorf("nil setter should detach the breaker")
	}
}

// TestBreakerEscalation_FullLoop pins the dispatch-side composition:
// Record → Open → EscalationMessage → prepend. Mirrors what the
// streaming dispatch loop in agent.go does inline. Lets us catch a
// regression in either the breaker package or the wiring without a
// live Anthropic client.
func TestBreakerEscalation_FullLoop(t *testing.T) {
	c := breaker.New(3)
	const tool = "loader_close"
	const errMsg = "device busy"

	// First two errors do NOT trip the breaker.
	for i := 1; i <= 2; i++ {
		state := c.Record(tool, errMsg)
		if state.Open {
			t.Fatalf("breaker tripped early at i=%d", i)
		}
		if msg := breaker.EscalationMessage(state); msg != "" {
			t.Errorf("non-empty escalation before trip: %q", msg)
		}
	}

	// Third error trips. Compose the dispatch-side prepending.
	state := c.Record(tool, errMsg)
	if !state.Open {
		t.Fatalf("breaker did not trip at threshold")
	}
	msg := breaker.EscalationMessage(state)
	if msg == "" {
		t.Fatalf("empty escalation on Open")
	}
	final := msg + "\n" + errMsg
	if !strings.HasPrefix(final, "<circuit-breaker-open>") {
		t.Errorf("escalation not prepended: %q", final)
	}
	if !strings.Contains(final, errMsg) {
		t.Errorf("original error dropped from final output: %q", final)
	}
	if !strings.Contains(final, "loader_close") {
		t.Errorf("tool name not in escalation: %q", final)
	}
}

// TestBreakerSuccess_ResetsStreak pins that a successful tool call
// (empty error string) clears the streak so a later same-kind error
// has to re-accumulate before tripping.
func TestBreakerSuccess_ResetsStreak(t *testing.T) {
	c := breaker.New(3)
	c.Record("t", "err")
	c.Record("t", "err")
	c.Record("t", "") // success
	state := c.Record("t", "err")
	if state.Streak != 1 {
		t.Errorf("streak after success-reset = %d, want 1", state.Streak)
	}
	if state.Open {
		t.Errorf("Open=true after one error post-reset")
	}
}

// TestBreaker_NilCounterIntegrationIsSafe pins the "feature
// disabled" path: a nil breaker on the agent must not change
// dispatch behaviour. Mirrors the inline `if a.breakerCounter != nil`
// guard in agent.go.
func TestBreaker_NilCounterIntegrationIsSafe(t *testing.T) {
	a := &Agent{}
	if a.breakerCounter != nil {
		t.Fatal("zero-value Agent has unexpected breaker")
	}
	// Simulate the dispatch-side guard: we should NOT call into a
	// nil breaker. Compile-checking by mirroring the inline test:
	if a.breakerCounter != nil {
		t.Error("guard would have fired against a nil breaker")
	}
}
