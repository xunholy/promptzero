package agent

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/mode"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/tools"
)

// TestDispatch_ModeBlocksHighRiskTransmit confirms a Sub-GHz TX
// primitive (Group=GroupFlipperSubGHz, Risk=High) is refused with
// ErrBlockedByMode when the agent is in Recon mode. This is the
// direct guarantee operators rely on: switching to a constrained
// mode actually prevents the transmit, even if the LLM advertises
// the tool and the dispatch catalogue still lists it.
func TestDispatch_ModeBlocksHighRiskTransmit(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.SetMode(mode.ModeRecon)

	// subghz_tx_key is registered with GroupFlipperSubGHz + risk.High.
	// Recon mode's allow-list excludes the SubGHz group, so dispatch
	// should refuse before touching the (nil) flipper handler.
	out, err := a.dispatch(context.Background(), "subghz_tx_key", map[string]interface{}{
		"key_hex":   "F00F00AA",
		"frequency": 433920000,
		"te":        400,
		"repeat":    3,
	})
	if err == nil {
		t.Fatalf("dispatch(subghz_tx_key) in Recon mode = (%q, nil), want refusal error", out)
	}
	if !errors.Is(err, ErrBlockedByMode) {
		t.Fatalf("dispatch error = %v, want errors.Is(err, ErrBlockedByMode) == true", err)
	}
	msg := err.Error()
	if !strings.Contains(msg, "subghz_tx_key") {
		t.Errorf("error %q does not name the tool — operators need the tool name in the rejection", msg)
	}
	if !strings.Contains(strings.ToLower(msg), "recon") {
		t.Errorf("error %q does not name the active mode — operators need the mode name to know what to switch", msg)
	}
}

// TestDispatch_ModeAllowsWhenStandardDefault confirms the zero-
// configured agent has Mode() == Standard. We don't drive a real
// dispatch through a non-mock handler here because that requires
// hardware; the "Standard does not gate" property is covered
// transitively by TestDispatch_ModeUnknownToolStillReportsUnknown
// (which only reaches the gate by passing the registry lookup).
func TestDispatch_ModeAllowsWhenStandardDefault(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	if got := a.Mode(); got != mode.ModeStandard {
		t.Fatalf("default agent mode = %q, want %q (Standard must be the zero-config default)", got, mode.ModeStandard)
	}
}

// TestDispatch_ModeUnknownToolStillReportsUnknown confirms the mode
// gate runs AFTER the registry lookup — an unknown tool name must
// still surface as "unknown tool", not as a mode-blocked rejection.
// (The opposite ordering would mask typos as policy refusals.)
func TestDispatch_ModeUnknownToolStillReportsUnknown(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.SetMode(mode.ModeStealth)
	_, err := a.dispatch(context.Background(), "this_tool_does_not_exist", map[string]interface{}{})
	if err == nil {
		t.Fatal("dispatch of unknown tool returned nil error")
	}
	if errors.Is(err, ErrBlockedByMode) {
		t.Fatalf("unknown tool surfaced as mode-blocked: %v — typos must not be confused with policy refusals", err)
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("unknown tool error = %q, want substring %q", err, "unknown tool")
	}
}

// TestSafeCallTextDelta_RecoversPanic pins the recover-wrapped
// streaming callback. A buggy operator-supplied textDelta
// callback that panics during streamOnce would otherwise crash
// the agent mid-stream; safeCallTextDelta keeps the stream
// accumulating.
func TestSafeCallTextDelta_RecoversPanic(t *testing.T) {
	called := false
	safeCallTextDelta(func(d TextDelta) {
		called = true
		panic("test-panic-marker-text-delta")
	}, TextDelta{Text: "x"})
	if !called {
		t.Errorf("callback was not invoked")
	}
	// safeCallTextDelta returning is itself the success — if the
	// recover didn't fire, the deferred panic would have crashed
	// the test goroutine.
}

// TestSafeCallStreamErr_RecoversPanic mirrors the above for the
// stream-error callback.
func TestSafeCallStreamErr_RecoversPanic(t *testing.T) {
	called := false
	safeCallStreamErr(func(err error) {
		called = true
		panic("test-panic-marker-stream-err")
	}, errors.New("upstream"))
	if !called {
		t.Errorf("callback was not invoked")
	}
}

// TestSafeCallUsage_RecoversPanic mirrors the above for the
// usage callback.
func TestSafeCallUsage_RecoversPanic(t *testing.T) {
	called := false
	safeCallUsage(func(u Usage) {
		called = true
		panic("test-panic-marker-usage")
	}, Usage{InputTokens: 100})
	if !called {
		t.Errorf("callback was not invoked")
	}
}

// TestSafeCallToolStatus_RecoversPanic pins the recover-wrapped
// tool-status callback. Operators install this to drive a UI
// progress indicator; a panic would otherwise crash the agent
// during dispatch even after the tool itself succeeded.
func TestSafeCallToolStatus_RecoversPanic(t *testing.T) {
	called := false
	safeCallToolStatus(func(e ToolEvent) {
		called = true
		panic("test-panic-marker-tool-status")
	}, ToolEvent{Phase: "start", Name: "test_tool"})
	if !called {
		t.Errorf("callback was not invoked")
	}
}

// TestSafeCallRetryNotify_RecoversPanic pins the recover-wrapped
// retry-notify callback. Defined alongside the agent.go-level
// safeCall* set even though the helper itself lives in retry.go.
func TestSafeCallRetryNotify_RecoversPanic(t *testing.T) {
	called := false
	safeCallRetryNotify(func(n RetryNotice) {
		called = true
		panic("test-panic-marker-retry-notify")
	}, RetryNotice{Attempt: 2, MaxAttempts: 4})
	if !called {
		t.Errorf("callback was not invoked")
	}
}

// TestDispatch_RecoversToolHandlerPanic pins the agent's safety
// guarantee: a buggy tool handler that panics must surface as a
// structured error from dispatch, not crash the whole agent
// process. With 200+ registered tools any single bad input
// shape (nil-deref, parser edge case, reflection panic) was a
// crash hazard before the recover wrap.
func TestDispatch_RecoversToolHandlerPanic(t *testing.T) {
	const panicToolName = "_test_panic_tool_for_dispatch_recover"
	tools.Register(tools.Spec{
		Name:        panicToolName,
		Description: "Test-only tool that always panics — pins the dispatch recover.",
		Schema:      json.RawMessage(`{"type":"object","properties":{}}`),
		Risk:        risk.Low,
		Group:       tools.GroupMetaUtil,
		Handler: func(_ context.Context, _ *tools.Deps, _ map[string]any) (string, error) {
			panic("test-panic-marker-x9q")
		},
	})

	a := agentForModelTest("claude-sonnet-4-6", nil)
	out, err := a.dispatch(context.Background(), panicToolName, map[string]interface{}{})
	if err == nil {
		t.Fatalf("dispatch returned nil error after a panicking handler, got out=%q", out)
	}
	if !strings.Contains(err.Error(), panicToolName) {
		t.Errorf("error %q should name the panicking tool", err.Error())
	}
	if !strings.Contains(err.Error(), "panicked") {
		t.Errorf("error %q should mention 'panicked'", err.Error())
	}
	if !strings.Contains(err.Error(), "test-panic-marker-x9q") {
		t.Errorf("error %q should include the recovered panic value", err.Error())
	}
}

// TestSetMode_EmptyResetsToStandard pins the contract: passing the
// empty Mode resets to Standard rather than leaving the agent in a
// degenerate "" state where no group is allowed.
func TestSetMode_EmptyResetsToStandard(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	a.SetMode(mode.ModeStealth)
	a.SetMode("") // explicit reset
	if got := a.Mode(); got != mode.ModeStandard {
		t.Errorf("SetMode(\"\") then Mode() = %q, want %q", got, mode.ModeStandard)
	}
}
