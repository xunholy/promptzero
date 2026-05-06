package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// TestBudgetCheckCallback_RefusesAtCap is the integration test:
// when the budget callback returns a non-nil error, Run() must
// abort BEFORE any streaming call is made — otherwise we burn
// tokens past the cap. The mock client is configured with a
// scripted response that we expect NEVER to be consumed; a
// successful test exits with the script untouched.
//
// Pre-this-fix the cost tracker emitted a 100% warning but Run()
// proceeded anyway. This test locks the v0.23 contract.
func TestBudgetCheckCallback_RefusesAtCap(t *testing.T) {
	// Scripted response we expect to be unused — the gate fires before
	// streaming begins.
	script := []testmocks.AnthropicScript{
		{Text: "this should never be reached"},
	}
	client := testmocks.NewMockAnthropic(t, script)
	cfg := &config.Config{Model: "claude-mock"}
	a := New(client, nil, cfg)

	a.SetBudgetCheckCallback(func() error {
		return ErrBudgetExceeded
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := a.Run(ctx, "anything")
	if err == nil {
		t.Fatal("Run should return error when budget callback refuses")
	}
	if !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("error must wrap ErrBudgetExceeded so callers can errors.Is; got: %v", err)
	}
}

// TestBudgetCheckCallback_NilDoesNotBlock verifies that an agent
// without a budget callback configured doesn't get the gate dropped
// on it — we should not regress callers that never opted into
// budget tracking. Asserts on the field directly to avoid spinning
// up a mock streaming session just to prove the gate didn't fire.
func TestBudgetCheckCallback_NilDoesNotBlock(t *testing.T) {
	a := NewForTest("test-model")
	if a.budgetCheckCb != nil {
		t.Error("default agent should have no budget callback")
	}
}

// TestBudgetCheckCallback_SetAndClear documents the setter contract:
// installing a callback and clearing via SetBudgetCheckCallback(nil)
// works as expected. Direct field assertion keeps this a pure unit
// test, no streaming machinery required.
func TestBudgetCheckCallback_SetAndClear(t *testing.T) {
	a := NewForTest("test-model")

	called := 0
	a.SetBudgetCheckCallback(func() error {
		called++
		return nil
	})
	if a.budgetCheckCb == nil {
		t.Fatal("SetBudgetCheckCallback didn't install the callback")
	}

	// Direct invocation through the stored callback verifies the
	// closure capture worked. Run-level integration is covered by
	// the RefusesAtCap test above.
	if err := a.budgetCheckCb(); err != nil {
		t.Errorf("nil-returning callback unexpectedly errored: %v", err)
	}
	if called != 1 {
		t.Errorf("callback invoked %d times via direct call, want 1", called)
	}

	// Clear it.
	a.SetBudgetCheckCallback(nil)
	if a.budgetCheckCb != nil {
		t.Error("SetBudgetCheckCallback(nil) didn't clear the callback")
	}
}

// TestErrBudgetExceeded_IsSentinel locks the sentinel-error contract.
// Callers (REPL, web) errors.Is against this to render a dedicated
// "budget exhausted" panel rather than a generic API-failure
// message — renaming or duplicating the variable would silently
// break that rendering.
func TestErrBudgetExceeded_IsSentinel(t *testing.T) {
	if ErrBudgetExceeded == nil {
		t.Fatal("ErrBudgetExceeded should be a non-nil sentinel error")
	}
	if !errors.Is(ErrBudgetExceeded, ErrBudgetExceeded) {
		t.Error("ErrBudgetExceeded must be reflexive under errors.Is")
	}
}
