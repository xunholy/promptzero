package workflows

import (
	"context"
	"testing"
)

// TestGateSubtool_NilHookApprovesByDefault locks the back-compat path
// so existing tests and orchestrators that don't install a hook still
// see every sub-step run.
func TestGateSubtool_NilHookApprovesByDefault(t *testing.T) {
	if !gateSubtool(context.Background(), Deps{}, "badusb_run", nil, "high") {
		t.Error("nil ConfirmSubtool should return true (approve by default)")
	}
}

// TestGateSubtool_HookDecidesOutcome verifies the hook's return value
// actually gates the step.
func TestGateSubtool_HookDecidesOutcome(t *testing.T) {
	deps := Deps{
		ConfirmSubtool: func(_ context.Context, _ string, _ interface{}, _ string) bool {
			return false
		},
	}
	if gateSubtool(context.Background(), deps, "badusb_run", nil, "high") {
		t.Error("hook returning false must propagate as gate-denied")
	}

	deps.ConfirmSubtool = func(_ context.Context, _ string, _ interface{}, _ string) bool {
		return true
	}
	if !gateSubtool(context.Background(), deps, "badusb_run", nil, "high") {
		t.Error("hook returning true must propagate as gate-approved")
	}
}

// TestGateSubtool_HookReceivesContext verifies the hook sees the
// workflow's cancellable ctx so it can honour timeouts / aborts.
func TestGateSubtool_HookReceivesContext(t *testing.T) {
	gotCtx := false
	deps := Deps{
		ConfirmSubtool: func(ctx context.Context, _ string, _ interface{}, _ string) bool {
			if ctx != nil {
				gotCtx = true
			}
			return true
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateSubtool(ctx, deps, "badusb_run", nil, "high")
	if !gotCtx {
		t.Error("hook should receive the workflow ctx")
	}
}
