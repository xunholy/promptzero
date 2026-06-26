// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/risk"
)

// toolBlock builds one tool_use content block for a scripted assistant turn.
func toolBlock(id, name, inputJSON string) anthropic.ContentBlockUnion {
	return anthropic.ContentBlockUnion{
		Type:  "tool_use",
		ID:    id,
		Name:  name,
		Input: json.RawMessage(inputJSON),
	}
}

// TestRunLoop_ConfirmDenyInLoop drives the confirm gate through the loop: a
// tool at/above the threshold prompts, a deny blocks execution, the refusal
// is fed back, and the model re-plans to completion.
func TestRunLoop_ConfirmDenyInLoop(t *testing.T) {
	a := NewForTest("test")
	a.SetConfirmThreshold(risk.Medium)
	prompts := 0
	a.SetConfirmCallback(func(_ context.Context, _ ConfirmRequest) ConfirmResponse {
		prompts++
		return ConfirmResponse{Decision: DecisionDeny}
	})
	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		if calls == 1 {
			return toolUseTurn("t1", "subghz_receive", `{"frequency":433920000}`), nil // Medium → prompts → deny
		}
		return textTurn("understood — not running it"), nil
	}
	out, err := a.Run(context.Background(), "receive subghz")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if prompts != 1 {
		t.Errorf("confirm prompts = %d, want 1", prompts)
	}
	if calls != 2 {
		t.Errorf("model turns = %d, want 2 (denied tool turn + re-plan)", calls)
	}
	if !strings.Contains(out, "understood") {
		t.Errorf("final answer = %q", out)
	}
}

// TestRunLoop_ApproveAllScoping pins the crown-jewel approve-all property:
// "approve all" auto-approves subsequent same-or-lower-risk tools in the
// same turn (the convenience), but must NOT silently escalate to a
// higher-risk tool — a tool above the approved tier re-prompts.
//
// The batch is [Low, Low, Medium] with the confirm threshold lowered to Low
// so all three reach the gate. Approve-all lands on the first Low tool
// (ceiling = Low); the second Low must be auto-approved (no prompt); the
// Medium tool exceeds the ceiling and must re-prompt. Using a Low offline
// tool (tool_search) for the approved legs keeps the test free of hardware
// execution — the escalating Medium tool is denied before it runs — so the
// assertions are purely about gating order.
func TestRunLoop_ApproveAllScoping(t *testing.T) {
	a := NewForTest("test")
	a.SetConfirmThreshold(risk.Low)

	var prompted []string // tool names that triggered a confirm prompt, in order
	a.SetConfirmCallback(func(_ context.Context, req ConfirmRequest) ConfirmResponse {
		prompted = append(prompted, req.Tool)
		if len(prompted) == 1 {
			return ConfirmResponse{Decision: DecisionApproveAll} // approve-all on the first (Low) tool
		}
		return ConfirmResponse{Decision: DecisionDeny} // deny the escalation so it doesn't execute
	})

	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		if calls == 1 {
			return &anthropic.Message{Content: []anthropic.ContentBlockUnion{
				toolBlock("t1", "tool_search", `{"query":"wifi"}`),           // Low → prompt → approve-all
				toolBlock("t2", "tool_search", `{"query":"nfc"}`),            // Low, <= ceiling → auto-approved
				toolBlock("t3", "subghz_receive", `{"frequency":433920000}`), // Medium, > ceiling → re-prompt
			}}, nil
		}
		return textTurn("done"), nil
	}

	if _, err := a.Run(context.Background(), "batch"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Exactly two prompts: the first Low tool and the escalating Medium tool.
	// The second Low tool must NOT appear (approve-all covered it); the
	// Medium MUST appear (approve-all must not escalate past its ceiling).
	if len(prompted) != 2 {
		t.Fatalf("confirm prompts = %v, want exactly 2 ([tool_search, subghz_receive])", prompted)
	}
	if prompted[0] != "tool_search" {
		t.Errorf("first prompt = %q, want tool_search", prompted[0])
	}
	if prompted[1] != "subghz_receive" {
		t.Errorf("second prompt = %q, want subghz_receive (the Medium tool must re-prompt, not auto-run)", prompted[1])
	}
}
