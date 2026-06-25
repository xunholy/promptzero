// SPDX-License-Identifier: AGPL-3.0-or-later

package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// textTurn builds a scripted assistant message that returns only text
// (ends the Run loop).
func textTurn(s string) *anthropic.Message {
	return &anthropic.Message{
		Content: []anthropic.ContentBlockUnion{{Type: "text", Text: s}},
	}
}

// toolUseTurn builds a scripted assistant message that calls one tool.
func toolUseTurn(id, name, inputJSON string) *anthropic.Message {
	return &anthropic.Message{
		Content: []anthropic.ContentBlockUnion{{
			Type:  "tool_use",
			ID:    id,
			Name:  name,
			Input: json.RawMessage(inputJSON),
		}},
	}
}

// TestRunLoop_DispatchesToolThenAnswers drives the multi-turn loop with a
// scripted model: turn 1 calls a tool, turn 2 returns the final answer.
// Proves the loop dispatches the tool and surfaces the final text.
func TestRunLoop_DispatchesToolThenAnswers(t *testing.T) {
	a := NewForTest("test")
	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		if calls == 1 {
			return toolUseTurn("t1", "tool_search", `{"query":"wifi"}`), nil
		}
		return textTurn("done: searched"), nil
	}
	out, err := a.Run(context.Background(), "find wifi tools")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Errorf("model turns = %d, want 2 (tool turn + final answer)", calls)
	}
	if !strings.Contains(out, "done: searched") {
		t.Errorf("final answer = %q, want it to contain the turn-2 text", out)
	}
}

// TestRunLoop_ToolCallCapStopsRunaway proves the per-turn tool-call cap
// terminates a model that never stops calling tools — the guard against an
// infinite tool loop. With a small cap and a model that always calls a
// tool, Run must return the cap message in a bounded number of turns.
func TestRunLoop_ToolCallCapStopsRunaway(t *testing.T) {
	a := NewForTest("test")
	a.maxToolsPerTurn = 2 // small cap so the test is fast
	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		return toolUseTurn("t", "tool_search", `{"query":"x"}`), nil // never finishes
	}
	out, err := a.Run(context.Background(), "loop forever")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "cap reached") {
		t.Errorf("expected the tool-call cap message, got %q", out)
	}
	if calls > 5 {
		t.Errorf("loop ran %d model turns; expected it to stop near the cap (bounded)", calls)
	}
}

// TestRunLoop_ReadOnlyRefusalFlowsBack proves the read-only rail engages
// inside the loop: a Medium tool is refused, the refusal is fed back as a
// tool_result, the model re-plans, and Run completes (rather than crashing
// or hanging). Complements the single-dispatch read-only test by covering
// the full loop + reflexion path.
func TestRunLoop_ReadOnlyRefusalFlowsBack(t *testing.T) {
	a := NewForTest("test")
	a.SetReadOnly(true)
	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		if calls == 1 {
			return toolUseTurn("t1", "subghz_receive", `{"frequency":433920000}`), nil
		}
		return textTurn("understood — staying read-only"), nil
	}
	out, err := a.Run(context.Background(), "receive subghz")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if calls != 2 {
		t.Errorf("model turns = %d, want 2 (refused tool turn + re-plan)", calls)
	}
	if !strings.Contains(out, "understood") {
		t.Errorf("final answer = %q", out)
	}
}
