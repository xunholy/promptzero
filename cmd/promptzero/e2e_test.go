package main

import (
	"context"
	"encoding/json"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/config"
	flippermock "github.com/xunholy/promptzero/internal/flipper/mock"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// e2eHarness wires a fresh Agent to the three testmocks (Flipper via pty,
// Anthropic via httptest, audit via sqlite under t.TempDir). Each test case
// gets its own harness so audit state, tool-call counters and script
// cursors stay isolated.
type e2eHarness struct {
	agent    *agent.Agent
	auditLog *audit.Log

	subghzMu   sync.Mutex
	subghzArgs [][]string
	devInfoN   atomic.Int32
}

func newE2EHarness(t *testing.T, script []testmocks.AnthropicScript) *e2eHarness {
	t.Helper()
	h := &e2eHarness{}

	flip := testmocks.NewMockFlipper(t,
		testmocks.WithFlipperHandler("device_info", func(args []string) string {
			h.devInfoN.Add(1)
			return flippermock.DefaultDeviceInfo
		}),
		testmocks.WithFlipperHandler("subghz", func(args []string) string {
			h.subghzMu.Lock()
			defer h.subghzMu.Unlock()
			h.subghzArgs = append(h.subghzArgs, slices.Clone(args))
			return "Transmission completed"
		}),
	)
	// DetectCapabilities runs a device_info during NewMockFlipper setup;
	// reset so assertions only count commands the agent issues.
	h.devInfoN.Store(0)

	client := testmocks.NewMockAnthropic(t, script)

	al, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	t.Cleanup(func() { _ = al.Close() })
	h.auditLog = al

	cfg := &config.Config{Model: "claude-mock"}
	a := agent.New(client, flip, cfg)
	a.SetAuditLog(al)
	h.agent = a
	return h
}

func (h *e2eHarness) subghzCalls() [][]string {
	h.subghzMu.Lock()
	defer h.subghzMu.Unlock()
	out := make([][]string, len(h.subghzArgs))
	for i, call := range h.subghzArgs {
		out[i] = slices.Clone(call)
	}
	return out
}

// TestAgentRun_ReadOnlyTool_HappyPath drives a full turn where the scripted
// model invokes system_info (risk Low → no confirmation), then emits a text
// reply echoing the device info. Proves tool dispatch, audit capture, and
// return-value plumbing fit together for the no-gate path.
func TestAgentRun_ReadOnlyTool_HappyPath(t *testing.T) {
	script := []testmocks.AnthropicScript{
		{Tool: "system_info", ToolID: "tool-1", ToolInput: map[string]any{}},
		{Text: "Device info: " + flippermock.DefaultDeviceInfo},
	}
	h := newE2EHarness(t, script)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := h.agent.Run(ctx, "what device am I connected to?")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(out, "MockDolphin") {
		t.Errorf("final text missing DefaultDeviceInfo marker: %q", out)
	}
	if got := h.devInfoN.Load(); got != 1 {
		t.Errorf("device_info dispatches = %d, want 1", got)
	}

	entries, err := h.auditLog.Query(10)
	if err != nil {
		t.Fatalf("audit.Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Tool != "system_info" {
		t.Errorf("audit tool = %q, want system_info", e.Tool)
	}
	if e.Risk != risk.Low.String() {
		t.Errorf("audit risk = %q, want %q", e.Risk, risk.Low.String())
	}
	if !e.Success {
		t.Errorf("audit success = false, want true")
	}
	if !strings.Contains(e.Output, "MockDolphin") {
		t.Errorf("audit output missing device_info marker: %q", e.Output)
	}
}

// TestAgentRun_RiskGatedTool_ConfirmApproves drives subghz_transmit (risk
// High) with a confirm callback that approves. Asserts the gate fires
// exactly once with the right request, the Flipper receives the expected
// CLI line, and audit records the call as a successful high-risk action.
func TestAgentRun_RiskGatedTool_ConfirmApproves(t *testing.T) {
	script := []testmocks.AnthropicScript{
		{
			Tool:      "subghz_transmit",
			ToolID:    "tool-1",
			ToolInput: map[string]any{"file": "/ext/subghz/garage.sub"},
		},
		{Text: "done"},
	}
	h := newE2EHarness(t, script)

	var (
		confirmCalls int
		confirmReq   agent.ConfirmRequest
	)
	h.agent.SetConfirmCallback(func(ctx context.Context, req agent.ConfirmRequest) agent.ConfirmResponse {
		confirmCalls++
		confirmReq = req
		return agent.ConfirmResponse{Decision: agent.DecisionApprove}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := h.agent.Run(ctx, "open the garage"); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if confirmCalls != 1 {
		t.Fatalf("confirm calls = %d, want 1", confirmCalls)
	}
	if confirmReq.Tool != "subghz_transmit" {
		t.Errorf("confirm tool = %q, want subghz_transmit", confirmReq.Tool)
	}
	if confirmReq.Risk != risk.High {
		t.Errorf("confirm risk = %v, want High", confirmReq.Risk)
	}
	var input map[string]any
	if err := json.Unmarshal(confirmReq.Input, &input); err != nil {
		t.Fatalf("unmarshal confirm input: %v", err)
	}
	if input["file"] != "/ext/subghz/garage.sub" {
		t.Errorf("confirm input[file] = %v, want /ext/subghz/garage.sub", input["file"])
	}

	calls := h.subghzCalls()
	if len(calls) != 1 {
		t.Fatalf("subghz calls = %d, want 1 (%v)", len(calls), calls)
	}
	want := []string{"tx_from_file", "/ext/subghz/garage.sub"}
	if !slices.Equal(calls[0], want) {
		t.Errorf("subghz args = %v, want %v", calls[0], want)
	}

	entries, err := h.auditLog.Query(10)
	if err != nil {
		t.Fatalf("audit.Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	if entries[0].Tool != "subghz_transmit" {
		t.Errorf("audit tool = %q, want subghz_transmit", entries[0].Tool)
	}
	if entries[0].Risk != risk.High.String() {
		t.Errorf("audit risk = %q, want %q", entries[0].Risk, risk.High.String())
	}
	if !entries[0].Success {
		t.Errorf("audit success = false, want true")
	}
}

// TestAgentRun_RiskGatedTool_ConfirmDenies drives the same high-risk tool
// but the callback refuses. Flipper must receive nothing, the audit row is
// a failed attempt tagged "user denied", and the final returned text comes
// from the scripted follow-up response the model emits after seeing the
// synthetic deny tool_result.
func TestAgentRun_RiskGatedTool_ConfirmDenies(t *testing.T) {
	const followUp = "skipped per user"
	script := []testmocks.AnthropicScript{
		{
			Tool:      "subghz_transmit",
			ToolID:    "tool-1",
			ToolInput: map[string]any{"file": "/ext/subghz/garage.sub"},
		},
		{Text: followUp},
	}
	h := newE2EHarness(t, script)

	h.agent.SetConfirmCallback(func(ctx context.Context, req agent.ConfirmRequest) agent.ConfirmResponse {
		return agent.ConfirmResponse{Decision: agent.DecisionDeny}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := h.agent.Run(ctx, "open the garage")
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out != followUp {
		t.Errorf("final text = %q, want %q (from scripted follow-up)", out, followUp)
	}

	if calls := h.subghzCalls(); len(calls) != 0 {
		t.Errorf("subghz calls = %d, want 0 (%v)", len(calls), calls)
	}

	entries, err := h.auditLog.Query(10)
	if err != nil {
		t.Fatalf("audit.Query: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Tool != "subghz_transmit" {
		t.Errorf("audit tool = %q, want subghz_transmit", e.Tool)
	}
	if e.Success {
		t.Errorf("audit success = true, want false for denied call")
	}
	if !strings.Contains(e.Output, "user denied") {
		t.Errorf("audit output missing 'user denied': %q", e.Output)
	}
	if e.Risk != risk.High.String() {
		t.Errorf("audit risk = %q, want %q", e.Risk, risk.High.String())
	}
}
