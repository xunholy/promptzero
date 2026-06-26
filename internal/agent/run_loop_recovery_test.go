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

// historyJSON marshals the agent's conversation history to the API wire
// form for substring assertions — a robust way to inspect what the loop
// actually fed back to the model (tool results, injected revisions,
// reflections) without unpacking the SDK's param block unions by hand.
func historyJSON(t *testing.T, a *Agent) string {
	t.Helper()
	b, err := json.Marshal(a.history)
	if err != nil {
		t.Fatalf("marshal history: %v", err)
	}
	return string(b)
}

// TestRunLoop_ReviseSkipsToolAndInjectsRevision drives DecisionRevise
// through the real loop: a gated tool must NOT execute, the synthesised
// tool_result must mark it skipped, and the operator's revision must be
// injected as a fresh user turn so the model re-plans. The unit tests
// cover the decision propagation; this covers the loop wiring.
func TestRunLoop_ReviseSkipsToolAndInjectsRevision(t *testing.T) {
	a := NewForTest("test")
	a.SetConfirmThreshold(risk.Medium)
	prompts := 0
	a.SetConfirmCallback(func(_ context.Context, _ ConfirmRequest) ConfirmResponse {
		prompts++
		return ConfirmResponse{Decision: DecisionRevise, Revision: "use 315 MHz instead of 433"}
	})
	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		if calls == 1 {
			return toolUseTurn("t1", "subghz_receive", `{"frequency":433920000}`), nil // Medium → gated → revise
		}
		return textTurn("re-planned"), nil
	}

	out, err := a.Run(context.Background(), "receive")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if prompts != 1 {
		t.Errorf("confirm prompts = %d, want 1", prompts)
	}
	h := historyJSON(t, a)
	if !strings.Contains(h, "operator requested revision instead of running this tool") {
		t.Error("skip tool_result missing from history (tool may have executed)")
	}
	if !strings.Contains(h, "use 315 MHz instead of 433") {
		t.Error("operator revision text was not injected into the conversation")
	}
	if !strings.Contains(h, "re-plan") {
		t.Error("re-plan prompt missing from injected revision")
	}
	if !strings.Contains(out, "re-planned") {
		t.Errorf("final answer = %q", out)
	}
}

// TestRunLoop_ReflexionFiresOnToolError verifies the reflexion feature is
// wired through Run: a failing tool triggers the reflector and its
// diagnosis is appended, delimited, to the tool result the model sees.
func TestRunLoop_ReflexionFiresOnToolError(t *testing.T) {
	a := NewForTest("test")
	reflectCalls := 0
	a.reflectorFn = func(_ context.Context, _ string, _ json.RawMessage, _ string) string {
		reflectCalls++
		return "try a valid hex string"
	}
	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		if calls == 1 {
			return toolUseTurn("t1", "cbor_decode", `{"hex":"zz"}`), nil // Low risk, fails cleanly
		}
		return textTurn("ok"), nil
	}

	if _, err := a.Run(context.Background(), "decode"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reflectCalls != 1 {
		t.Errorf("reflector calls = %d, want 1", reflectCalls)
	}
	h := historyJSON(t, a)
	// json.Marshal HTML-escapes the <reflection> tag, so match the wrapper
	// word plus the diagnosis text.
	if !strings.Contains(h, "reflection") || !strings.Contains(h, "try a valid hex string") {
		t.Errorf("reflection not appended to the tool result in history:\n%s", h)
	}
}

// TestRunLoop_ReflexionCapPerTurn proves the per-turn reflection counter is
// shared across every tool in the turn: four failing tools in one
// assistant message must trigger at most maxReflectionsPerTurn reflections,
// not one per tool.
func TestRunLoop_ReflexionCapPerTurn(t *testing.T) {
	a := NewForTest("test")
	reflectCalls := 0
	a.reflectorFn = func(_ context.Context, _ string, _ json.RawMessage, _ string) string {
		reflectCalls++
		return "diagnosis"
	}
	calls := 0
	a.turnFn = func(_ context.Context, _ string, _ []anthropic.ToolUnionParam) (*anthropic.Message, error) {
		calls++
		if calls == 1 {
			return &anthropic.Message{Content: []anthropic.ContentBlockUnion{
				toolBlock("t1", "cbor_decode", `{"hex":"zz"}`),
				toolBlock("t2", "cbor_decode", `{"hex":"zz"}`),
				toolBlock("t3", "cbor_decode", `{"hex":"zz"}`),
				toolBlock("t4", "cbor_decode", `{"hex":"zz"}`),
			}}, nil
		}
		return textTurn("done"), nil
	}

	if _, err := a.Run(context.Background(), "decode many"); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if reflectCalls != maxReflectionsPerTurn {
		t.Errorf("reflector calls = %d, want %d (per-turn cap across all tools)", reflectCalls, maxReflectionsPerTurn)
	}
}
