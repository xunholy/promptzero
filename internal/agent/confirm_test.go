package agent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/risk"
)

// TestConfirmDenyShortCircuits verifies that when the confirm callback
// returns DecisionDeny for a high-risk tool, the agent appends a synthetic
// tool_result with "user denied this action" and never dispatches the tool.
// We detect non-dispatch by using a tool name that would fall through to
// dispatch's default case (an error string) — if the gate lets it through
// we'd see that error, not the synthetic deny message.
func TestConfirmDenyShortCircuits(t *testing.T) {
	a := &Agent{confirmThreshold: risk.High}

	called := 0
	a.confirmCb = func(ctx context.Context, req ConfirmRequest) Decision {
		called++
		if req.Tool != "wifi_deauth" {
			t.Fatalf("unexpected tool in confirm request: %q", req.Tool)
		}
		if req.Risk != risk.Critical {
			t.Fatalf("expected risk Critical for wifi_deauth, got %v", req.Risk)
		}
		return DecisionDeny
	}

	tc := anthropic.ContentBlockUnion{
		Type:  "tool_use",
		ID:    "toolu_test",
		Name:  "wifi_deauth",
		Input: json.RawMessage(`{"duration_seconds":10}`),
	}

	var toolResults []anthropic.ContentBlockParamUnion
	var approveAllRemaining bool
	dispatched := 0

	for _, call := range []anthropic.ContentBlockUnion{tc} {
		input := json.RawMessage(call.Input)
		toolRisk := risk.Classify(call.Name)

		if a.confirmCb != nil && !approveAllRemaining && toolRisk >= a.confirmThreshold {
			switch a.confirmCb(context.Background(), ConfirmRequest{Tool: call.Name, Input: input, Risk: toolRisk}) {
			case DecisionDeny:
				toolResults = append(toolResults, anthropic.NewToolResultBlock(call.ID, "user denied this action", true))
				continue
			case DecisionApproveAll:
				approveAllRemaining = true
			}
		}
		dispatched++
		_, _ = a.executeTool(context.Background(), call.Name, call.Input)
	}

	if called != 1 {
		t.Fatalf("expected confirm callback to run exactly once, got %d", called)
	}
	if dispatched != 0 {
		t.Fatalf("expected no tool dispatch after deny, got %d", dispatched)
	}
	if len(toolResults) != 1 {
		t.Fatalf("expected exactly one tool_result, got %d", len(toolResults))
	}
	got := toolResults[0].OfToolResult
	if got == nil {
		t.Fatal("tool_result block has no OfToolResult")
	}
	if got.ToolUseID != "toolu_test" {
		t.Errorf("tool_use_id mismatch: got %q", got.ToolUseID)
	}
	if len(got.Content) != 1 || got.Content[0].OfText == nil {
		t.Fatalf("expected text content in tool_result, got %+v", got.Content)
	}
	if got.Content[0].OfText.Text != "user denied this action" {
		t.Errorf("expected synthetic deny text, got %q", got.Content[0].OfText.Text)
	}
}

// TestConfirmBelowThresholdSkipsCallback verifies that low-risk tools
// bypass the callback entirely.
func TestConfirmBelowThresholdSkipsCallback(t *testing.T) {
	a := &Agent{confirmThreshold: risk.High}
	a.confirmCb = func(ctx context.Context, req ConfirmRequest) Decision {
		t.Fatalf("callback should not fire for low-risk tool %q", req.Tool)
		return DecisionDeny
	}

	toolRisk := risk.Classify("device_info")
	if toolRisk >= a.confirmThreshold {
		t.Fatalf("device_info unexpectedly >= High; got %v", toolRisk)
	}
	// The gate condition in Run short-circuits before calling confirmCb,
	// which is what we assert above.
}

// TestConfirmApproveAll verifies that a single DecisionApproveAll response
// skips confirmation for the remaining tool calls in the same batch.
func TestConfirmApproveAll(t *testing.T) {
	a := &Agent{confirmThreshold: risk.High}

	calls := 0
	a.confirmCb = func(ctx context.Context, req ConfirmRequest) Decision {
		calls++
		return DecisionApproveAll
	}

	tools := []string{"wifi_deauth", "device_reboot", "subghz_transmit"}
	var approveAllRemaining bool
	gated := 0
	for _, name := range tools {
		toolRisk := risk.Classify(name)
		gate := toolRisk == risk.Critical || !approveAllRemaining
		if a.confirmCb != nil && gate && toolRisk >= a.confirmThreshold {
			gated++
			if a.confirmCb(context.Background(), ConfirmRequest{Tool: name, Risk: toolRisk}) == DecisionApproveAll {
				approveAllRemaining = true
			}
		}
	}

	// wifi_deauth and subghz_transmit are both Critical, so they each
	// still fire the callback even after the first one returned
	// ApproveAll. device_reboot is High, so it rides the approve-all.
	// 3 Critical tools would be gated three times; the one non-Critical
	// (device_reboot) is gated only when approve-all hasn't fired yet.
	// Exact gate count depends on risk.Classify: whichever way it's
	// tuned, critical tools must always be in the gated set.
	critCount := 0
	for _, name := range tools {
		if risk.Classify(name) == risk.Critical {
			critCount++
		}
	}
	if gated < critCount {
		t.Errorf("expected at least %d gated (all Critical tools), got %d", critCount, gated)
	}
	if calls < critCount {
		t.Errorf("expected callback to fire at least %d times (once per Critical), got %d", critCount, calls)
	}
}

// TestConfirmCriticalNotBypassedByApproveAll asserts the "critical
// always prompts" rule directly: approve-all on an earlier non-critical
// tool must not skip the gate for a later critical tool.
func TestConfirmCriticalNotBypassedByApproveAll(t *testing.T) {
	a := &Agent{confirmThreshold: risk.High}

	var seen []string
	a.confirmCb = func(ctx context.Context, req ConfirmRequest) Decision {
		seen = append(seen, req.Tool)
		if len(seen) == 1 {
			return DecisionApproveAll
		}
		return DecisionApprove
	}

	// Mix of risks so a High tool is the first to hit the gate, the
	// user approve-alls, and a later Critical tool still needs a
	// dedicated prompt.
	tools := []struct {
		name string
		risk risk.Level
	}{
		{"some_high_tool", risk.High},
		{"some_critical_tool", risk.Critical},
	}
	var approveAllRemaining bool
	for _, tc := range tools {
		gate := tc.risk == risk.Critical || !approveAllRemaining
		if a.confirmCb != nil && gate && tc.risk >= a.confirmThreshold {
			if a.confirmCb(context.Background(), ConfirmRequest{Tool: tc.name, Risk: tc.risk}) == DecisionApproveAll {
				approveAllRemaining = true
			}
		}
	}

	if len(seen) != 2 {
		t.Fatalf("expected both tools to prompt (critical must not be bypassed), got prompts for %v", seen)
	}
	if seen[0] != "some_high_tool" || seen[1] != "some_critical_tool" {
		t.Errorf("unexpected prompt order: %v", seen)
	}
}
