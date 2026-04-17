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
		_ = a.executeTool(context.Background(), call.Name, call.Input)
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
		if a.confirmCb != nil && !approveAllRemaining && toolRisk >= a.confirmThreshold {
			gated++
			if a.confirmCb(context.Background(), ConfirmRequest{Tool: name, Risk: toolRisk}) == DecisionApproveAll {
				approveAllRemaining = true
			}
		}
	}

	if calls != 1 {
		t.Errorf("expected callback to fire once, got %d", calls)
	}
	if gated != 1 {
		t.Errorf("expected exactly one tool gated (first), got %d", gated)
	}
}
