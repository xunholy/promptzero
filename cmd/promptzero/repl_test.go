package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/risk"
)

// makeConfirmState builds a confirmState for testing resolveConfirmKey.
// If gate is nil the field is left nil (gate not wired, any time is fine).
func makeConfirmState(r risk.Level, gate *agent.ConfirmDelayGate) *confirmState {
	return &confirmState{
		req: agent.ConfirmRequest{
			Tool:  "test_tool",
			Risk:  r,
			Input: json.RawMessage(`{}`),
		},
		result: make(chan agent.ConfirmResponse, 1),
		gate:   gate,
	}
}

// TestResolveConfirmKey_YBeforeDelay asserts that pressing 'y' before the
// 2-second window elapses is silently rejected (returns false, no response
// sent to the result channel).
func TestResolveConfirmKey_YBeforeDelay(t *testing.T) {
	// Gate with a 1-hour delay (never opens during this test).
	gate := agent.NewConfirmDelayGate(1 * time.Hour)
	gate.Show()

	cs := makeConfirmState(risk.High, gate)
	ed := newTestEditor()

	resolved := resolveConfirmKey(cs, keyEvent{kind: keyRune, r: 'y'}, ed)
	if resolved {
		t.Fatal("resolveConfirmKey should return false when gate is closed (before 2s delay)")
	}
	// No response should have been sent.
	select {
	case resp := <-cs.result:
		t.Fatalf("unexpected response before delay elapsed: %+v", resp)
	default:
	}
}

// TestResolveConfirmKey_YAfterDelay asserts that pressing 'y' after the
// delay elapses is accepted and sends DecisionApprove.
func TestResolveConfirmKey_YAfterDelay(t *testing.T) {
	// Gate with zero delay — open immediately without Show().
	gate := agent.NewConfirmDelayGate(0)

	cs := makeConfirmState(risk.High, gate)
	ed := newTestEditor()

	resolved := resolveConfirmKey(cs, keyEvent{kind: keyRune, r: 'y'}, ed)
	if !resolved {
		t.Fatal("resolveConfirmKey should return true when gate is open")
	}
	var resp agent.ConfirmResponse
	select {
	case resp = <-cs.result:
	default:
		t.Fatal("expected a response on the result channel")
	}
	if resp.Decision != agent.DecisionApprove {
		t.Errorf("decision = %v, want DecisionApprove", resp.Decision)
	}
}

// TestResolveConfirmKey_NAlwaysPasses asserts that pressing 'n' (deny)
// always resolves the prompt regardless of gate state.
func TestResolveConfirmKey_NAlwaysPasses(t *testing.T) {
	// Gate with a very long delay — should not block 'n'.
	gate := agent.NewConfirmDelayGate(1 * time.Hour)
	gate.Show()

	cs := makeConfirmState(risk.High, gate)
	ed := newTestEditor()

	resolved := resolveConfirmKey(cs, keyEvent{kind: keyRune, r: 'n'}, ed)
	if !resolved {
		t.Fatal("'n' should always resolve the prompt even when gate is closed")
	}
	var resp agent.ConfirmResponse
	select {
	case resp = <-cs.result:
	default:
		t.Fatal("expected a response on the result channel for 'n'")
	}
	if resp.Decision != agent.DecisionDeny {
		t.Errorf("decision = %v, want DecisionDeny", resp.Decision)
	}
}

// TestResolveConfirmKey_AllBeforeDelay asserts that typing "all"+Enter
// before the delay elapses is rejected (gate not open).
func TestResolveConfirmKey_AllBeforeDelay(t *testing.T) {
	gate := agent.NewConfirmDelayGate(1 * time.Hour)
	gate.Show()

	cs := makeConfirmState(risk.High, gate)
	cs.typing = []rune("all")
	cs.typingKind = typingFreeText
	ed := newTestEditor()

	resolved := resolveConfirmKey(cs, keyEvent{kind: keyEnter}, ed)
	if resolved {
		t.Fatal("'all'+Enter should be rejected when gate is closed")
	}
	// typing should be cleared so the user can retry after the delay.
	if cs.typing != nil {
		t.Errorf("cs.typing should be reset to nil after gate-closed rejection, got %v", cs.typing)
	}
}

// TestResolveConfirmKey_AllAfterDelay asserts that typing "all"+Enter
// after the delay elapses is accepted.
func TestResolveConfirmKey_AllAfterDelay(t *testing.T) {
	gate := agent.NewConfirmDelayGate(0)

	cs := makeConfirmState(risk.High, gate)
	cs.typing = []rune("all")
	cs.typingKind = typingFreeText
	ed := newTestEditor()

	resolved := resolveConfirmKey(cs, keyEvent{kind: keyEnter}, ed)
	if !resolved {
		t.Fatal("'all'+Enter should be accepted when gate is open")
	}
	var resp agent.ConfirmResponse
	select {
	case resp = <-cs.result:
	default:
		t.Fatal("expected a response on the result channel")
	}
	if resp.Decision != agent.DecisionApproveAll {
		t.Errorf("decision = %v, want DecisionApproveAll", resp.Decision)
	}
}

// TestResolveConfirmKey_ConfirmWordCriticalAfterDelay asserts that typing
// "confirm"+Enter for a Critical-risk prompt is accepted after the delay.
func TestResolveConfirmKey_ConfirmWordCriticalAfterDelay(t *testing.T) {
	gate := agent.NewConfirmDelayGate(0)

	cs := makeConfirmState(risk.Critical, gate)
	cs.typing = []rune("confirm")
	cs.typingKind = typingFreeText
	ed := newTestEditor()

	resolved := resolveConfirmKey(cs, keyEvent{kind: keyEnter}, ed)
	if !resolved {
		t.Fatal("'confirm'+Enter should be accepted for Critical when gate is open")
	}
	var resp agent.ConfirmResponse
	select {
	case resp = <-cs.result:
	default:
		t.Fatal("expected a response on the result channel")
	}
	if resp.Decision != agent.DecisionApprove {
		t.Errorf("decision = %v, want DecisionApprove", resp.Decision)
	}
}

// TestResolveConfirmKey_HintOnGateClosed verifies that a "wait …" hint is
// printed to stderr when the gate rejects a 'y' keystroke.
func TestResolveConfirmKey_HintOnGateClosed(t *testing.T) {
	gate := agent.NewConfirmDelayGate(1 * time.Hour)
	gate.Show()

	cs := makeConfirmState(risk.High, gate)
	ed := newTestEditor()

	out := captureStderr(t, func() {
		resolveConfirmKey(cs, keyEvent{kind: keyRune, r: 'y'}, ed)
	})
	if !strings.Contains(out, "wait") {
		t.Errorf("expected a 'wait' hint in stderr when gate is closed, got %q", out)
	}
}
