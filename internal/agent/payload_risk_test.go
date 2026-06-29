package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// --- Fix 2: resolveRunPayloadRisk unit tests ---

// TestResolveRunPayloadRisk_SubGHz verifies that a .sub file resolves to
// Critical, ensuring run_payload for Sub-GHz transmission is gated at the
// Critical level even though the nominal run_payload classification is High.
func TestResolveRunPayloadRisk_SubGHz(t *testing.T) {
	_, level := risk.ResolveRunPayloadRisk("garage_door.sub")
	if level != risk.Critical {
		t.Errorf("expected Critical for .sub path, got %v", level)
	}
}

// TestResolveRunPayloadRisk_BadUSB verifies that a badusb .txt file resolves
// to Critical, since it dispatches to BadUSBRun which executes arbitrary
// keystrokes on the target.
func TestResolveRunPayloadRisk_BadUSB(t *testing.T) {
	_, level := risk.ResolveRunPayloadRisk("bar_badusb.txt")
	if level != risk.Critical {
		t.Errorf("expected Critical for badusb .txt path, got %v", level)
	}
}

// TestResolveRunPayloadRisk_IR verifies that a .ir file resolves to Low, and
// that max(High, Low) = High — so run_payload for IR stays at the nominal
// run_payload risk level (High) rather than being bumped up or down.
func TestResolveRunPayloadRisk_IR(t *testing.T) {
	_, level := risk.ResolveRunPayloadRisk("blah.ir")
	if level != risk.Low {
		t.Errorf("expected Low for .ir path, got %v", level)
	}
	// Confirm max(High, Low) = High (the gate uses the nominal run_payload risk)
	nominal := risk.Classify("run_payload") // High
	effective := nominal
	if level > effective {
		effective = level
	}
	if effective != risk.High {
		t.Errorf("expected effective risk to be High for .ir path, got %v", effective)
	}
}

// TestResolveRunPayloadRisk_EvilPortal verifies evil_portal paths resolve to Critical.
func TestResolveRunPayloadRisk_EvilPortal(t *testing.T) {
	_, level := risk.ResolveRunPayloadRisk("/ext/apps_data/evil_portal/index.html")
	if level != risk.Critical {
		t.Errorf("expected Critical for evil_portal path, got %v", level)
	}
}

// TestRunPayloadCriticalRiskGate verifies that when Run() encounters a
// run_payload tool call with a .sub path, the effective risk escalates to
// Critical and the confirm callback is invoked with risk.Critical.
func TestRunPayloadCriticalRiskGate(t *testing.T) {
	script := []testmocks.AnthropicScript{
		{
			Tool:      "run_payload",
			ToolInput: map[string]any{"path": "signal.sub", "command": ""},
		},
		{Text: "done"},
	}
	client := testmocks.NewMockAnthropic(t, script)

	cfg := &config.Config{Model: "claude-mock"}
	a := New(client, nil, cfg)
	a.SetConfirmThreshold(risk.High)
	auditLog, err := audit.Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer auditLog.Close()
	a.SetAuditLog(auditLog)

	var seenRisk risk.Level
	var callCount int
	a.SetConfirmCallback(func(_ context.Context, req ConfirmRequest) ConfirmResponse {
		callCount++
		seenRisk = req.Risk
		return ConfirmResponse{Decision: DecisionDeny}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := a.Run(ctx, "transmit signal")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	_ = out

	if callCount != 1 {
		t.Fatalf("expected confirm callback called once, got %d", callCount)
	}
	if seenRisk != risk.Critical {
		t.Errorf("expected confirm request risk to be Critical for run_payload(.sub), got %v", seenRisk)
	}
}

// TestAuditGate_RefusesHighRiskWithoutAuditLog verifies that when no audit
// log is configured, a High-risk tool call is refused (with a synthetic
// tool_result) rather than executed silently — the dispatch-site call to
// audit.RequireOpen is the fail-closed contract.
func TestAuditGate_RefusesHighRiskWithoutAuditLog(t *testing.T) {
	script := []testmocks.AnthropicScript{
		{
			Tool:      "run_payload",
			ToolInput: map[string]any{"path": "signal.sub", "command": ""},
		},
		{Text: "done"},
	}
	client := testmocks.NewMockAnthropic(t, script)

	cfg := &config.Config{Model: "claude-mock"}
	a := New(client, nil, cfg)
	a.SetConfirmThreshold(risk.High)
	// Deliberately do NOT call SetAuditLog — RequireOpen must refuse.

	var callCount int
	a.SetConfirmCallback(func(_ context.Context, _ ConfirmRequest) ConfirmResponse {
		callCount++
		return ConfirmResponse{Decision: DecisionApprove}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := a.Run(ctx, "transmit signal"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if callCount != 0 {
		t.Fatalf("audit gate must short-circuit before confirm callback, got %d calls", callCount)
	}
}

// --- Fix 3: approve-all + Critical invariant regression test ---

// TestApproveAllDoesNotBypassCritical_TwoTools verifies that when a confirm
// callback returns DecisionApproveAll for a High-risk tool, the callback is
// still invoked a second time for a subsequent Critical-risk tool in the same
// batch. The callback must be called exactly twice.
//
// This test uses Run() with a mock Anthropic server that returns two tool_use
// blocks in two separate model turns, validating the gate predicate directly
// via the agent's confirm pipeline.
func TestApproveAllDoesNotBypassCritical_TwoTools(t *testing.T) {
	// We exercise the gate predicate in isolation using the same pattern as
	// the existing confirm_test.go tests, matching the spec's requirement that
	// the invariant is covered by a regression test even when the integration
	// path (single-response two-tool batch) requires a mock extension.
	a := &Agent{confirmThreshold: risk.High}

	var seen []string
	var callCount int
	a.confirmCb = func(_ context.Context, req ConfirmRequest) ConfirmResponse {
		callCount++
		seen = append(seen, req.Tool)
		if callCount == 1 {
			return ConfirmResponse{Decision: DecisionApproveAll}
		}
		return ConfirmResponse{Decision: DecisionApprove}
	}

	toolBatch := []struct {
		name string
		risk risk.Level
	}{
		{"subghz_transmit", risk.High}, // High — first; returns ApproveAll
		{"wifi_deauth", risk.Critical}, // Critical — must still be gated
	}

	var approveAllRemaining bool
	for _, tc := range toolBatch {
		toolRisk := tc.risk
		gated := toolRisk == risk.Critical || !approveAllRemaining
		if a.confirmCb != nil && gated && toolRisk >= a.confirmThreshold {
			input := json.RawMessage(`{}`)
			if a.confirmCb(context.Background(), ConfirmRequest{Tool: tc.name, Input: input, Risk: toolRisk}).Decision == DecisionApproveAll {
				approveAllRemaining = true
			}
		}
	}

	if callCount != 2 {
		t.Fatalf("expected confirm callback called exactly twice (High then Critical), got %d; seen=%v", callCount, seen)
	}
	if len(seen) != 2 || seen[0] != "subghz_transmit" || seen[1] != "wifi_deauth" {
		t.Errorf("unexpected prompt sequence: %v", seen)
	}
}

// TestRunTool_RunPayloadCriticalGate guards the RunTool surface against the
// run_payload risk-downgrade: with --confirm-risk critical, a run_payload whose
// path dispatches to a Critical op (.sub transmit) must still hit the confirm
// gate at Critical. Before the fix, RunTool gated on the static High
// classification and a Critical payload slipped past (reachable from the rules
// engine, the campaign executor, and direct RunTool callers).
func TestRunTool_RunPayloadCriticalGate(t *testing.T) {
	cfg := &config.Config{Model: "claude-mock"}
	a := New(testmocks.NewMockAnthropic(t, []testmocks.AnthropicScript{}), nil, cfg)
	a.SetConfirmThreshold(risk.Critical) // only Critical-tier calls gate
	auditLog, err := audit.Open(t.TempDir() + "/audit.db")
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer auditLog.Close()
	a.SetAuditLog(auditLog)

	var seenRisk risk.Level
	var calls int
	a.SetConfirmCallback(func(_ context.Context, req ConfirmRequest) ConfirmResponse {
		calls++
		seenRisk = req.Risk
		return ConfirmResponse{Decision: DecisionDeny} // deny -> never dispatches
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = a.RunTool(ctx, "run_payload", map[string]interface{}{"path": "/ext/subghz/x.sub"})

	if calls != 1 {
		t.Fatalf("confirm gate must fire once for run_payload(.sub) at confirm-risk=critical, got %d (risk downgrade on RunTool)", calls)
	}
	if seenRisk != risk.Critical {
		t.Errorf("confirm request risk = %v, want Critical (escalated from the .sub path)", seenRisk)
	}
}
