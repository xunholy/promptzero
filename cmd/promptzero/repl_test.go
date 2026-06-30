package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/risk"
	streampkg "github.com/xunholy/promptzero/internal/streaming"
	"github.com/xunholy/promptzero/internal/testmocks"
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

// TestRenderStreamFrame_RendersPlainPayload pins the happy path: a
// printable, short frame becomes a single dim, indented line. The
// exact ANSI sequences are not asserted (terminal-style globals can
// vary in test contexts) — only that the payload is preserved and
// the leading indent / dim marker shape is intact.
func TestRenderStreamFrame_RendersPlainPayload(t *testing.T) {
	got := renderStreamFrame(streampkg.Frame{
		Tool:  "subghz_receive",
		Bytes: []byte("Princeton  433.92  KEY=DEADBEEF"),
	})
	if got == "" {
		t.Fatal("renderStreamFrame returned empty for a non-empty payload")
	}
	if !strings.Contains(got, "Princeton") {
		t.Errorf("rendered frame missing payload: %q", got)
	}
	if !strings.Contains(got, "·") {
		t.Errorf("rendered frame missing the · marker: %q", got)
	}
}

// TestRenderStreamFrame_EmptyPayloadIsSilent pins that an empty or
// whitespace-only frame renders as the empty string — the REPL skips
// printing those, so a chatty parser that emits a stray newline frame
// doesn't pollute the scroll area.
func TestRenderStreamFrame_EmptyPayloadIsSilent(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("\n"), []byte("   "), []byte("\r\n  \n\r")} {
		if got := renderStreamFrame(streampkg.Frame{Bytes: in}); got != "" {
			t.Errorf("renderStreamFrame(%q) = %q, want empty string", in, got)
		}
	}
}

// TestRenderStreamFrame_QuotesControlChars pins the hostile-capture
// defence: a frame containing ANSI escapes or NUL bytes is %q-quoted
// before render. A captured BLE device name set to
// "\x1b[31mEVIL\x1b[0m" must NOT inject raw ANSI into the operator's
// terminal.
func TestRenderStreamFrame_QuotesControlChars(t *testing.T) {
	got := renderStreamFrame(streampkg.Frame{
		Tool:  "marauder_scan",
		Bytes: []byte("\x1b[31mEVIL\x1b[0m"),
	})
	if got == "" {
		t.Fatal("renderStreamFrame returned empty for a non-empty hostile payload")
	}
	// Raw ESC must not appear — %q would have rendered it as \x1b.
	if strings.Contains(got, "\x1b[31m") {
		t.Errorf("rendered frame leaked raw ANSI: %q", got)
	}
	if !strings.Contains(got, `\x1b`) {
		t.Errorf("rendered frame did not escape ANSI: %q", got)
	}
}

// TestNeedsQuote pins the predicate the renderer uses: only C0
// control bytes (< 0x20) and DEL (0x7f) trigger quoting. The
// motivating attack is ANSI-escape injection from hardware-supplied
// strings (a captured BLE device name like "\x1b[31mEVIL"). UTF-8
// printable bytes above 0x7f are NOT quoted — non-ASCII payloads
// (e.g. an emoji in a chat-app capture) render as themselves.
func TestNeedsQuote(t *testing.T) {
	tests := map[string]bool{
		"plain ASCII": false,
		"":            false,
		"with\ttab":   true,
		"esc\x1b[31m": true,
		"nul\x00byte": true,
		"del\x7fchar": true,
		"emoji 🎉":     false, // printable UTF-8 above 0x7f is fine
	}
	for in, want := range tests {
		if got := needsQuote(in); got != want {
			t.Errorf("needsQuote(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestMetricToolLabel pins the Prometheus tool-label cardinality guard: a
// registered tool name passes through, while any unregistered name (a
// hallucinated or injection-supplied tool_use name, including a fake
// "workflow_" one) collapses to the bounded sentinel so /metrics series can't
// grow unboundedly.
func TestMetricToolLabel(t *testing.T) {
	if got := metricToolLabel("tool_search"); got != "tool_search" {
		t.Errorf("registered tool should pass through, got %q", got)
	}
	for _, n := range []string{"aaa1", "workflow_evil_injected", "</untrusted-hardware-output>", "", "tool_searchX"} {
		if got := metricToolLabel(n); got != metricUnknownTool {
			t.Errorf("unregistered %q: got %q, want %q", n, got, metricUnknownTool)
		}
	}
}

// TestApplyWatchPersona_ScopesAndRestores pins that a watch rule's persona is
// applied for its turn and then reverted, so the rule's persona (and its tool
// scope) does not leak into the operator's later interactive turns. Empty or
// unknown rule personas leave the active persona untouched and return no
// restore.
func TestApplyWatchPersona_ScopesAndRestores(t *testing.T) {
	reg := persona.NewRegistry()
	def, ok := reg.Get("default")
	if !ok {
		t.Fatal("built-in 'default' persona missing")
	}
	ai := agent.New(testmocks.NewMockAnthropic(t, []testmocks.AnthropicScript{}), &flipper.Flipper{}, &config.Config{Model: "claude-mock"})
	ai.SetPersona(def)

	restore := applyWatchPersona(ai, reg, "defender")
	if restore == nil {
		t.Fatal("expected a restore func for a known rule persona")
	}
	if got := ai.Persona(); got == nil || got.Name != "defender" {
		t.Fatalf("persona not switched to defender for the watch turn, got %v", got)
	}
	restore()
	if got := ai.Persona(); got == nil || got.Name != "default" {
		t.Errorf("persona not restored after the watch turn, got %v", got)
	}

	// Empty / unknown rule persona: no switch, nil restore.
	if applyWatchPersona(ai, reg, "") != nil {
		t.Error("empty rule persona should return nil restore")
	}
	if applyWatchPersona(ai, reg, "nonexistent-persona") != nil {
		t.Error("unknown rule persona should return nil restore")
	}
	if got := ai.Persona(); got == nil || got.Name != "default" {
		t.Errorf("active persona changed by a no-op apply, got %v", got)
	}
}
