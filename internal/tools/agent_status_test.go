// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/config"
)

// TestAgentStatus_ReportsLivePosture verifies the handler surfaces the
// live read-only / mode / persona posture when the agent wires the
// Posture resolver, plus audit + model.
func TestAgentStatus_ReportsLivePosture(t *testing.T) {
	d := &Deps{
		Audit:  &audit.Log{}, // non-nil → audit_enabled true (handler only checks != nil)
		Config: &config.Config{Model: "claude-opus-4-8"},
		Posture: func() AgentPosture {
			return AgentPosture{
				ReadOnly: true, Mode: "recon", Persona: "blue-team-audit",
				ConfirmRisk: "high", ConfirmEnabled: true,
			}
		},
	}
	out, err := agentStatusHandler(context.Background(), d, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r agentStatusReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, out)
	}
	if r.ReadOnly == nil || !*r.ReadOnly {
		t.Errorf("read_only = %v, want true", r.ReadOnly)
	}
	if r.Mode != "recon" || r.Persona != "blue-team-audit" {
		t.Errorf("mode/persona = %q/%q, want recon/blue-team-audit", r.Mode, r.Persona)
	}
	if r.Model != "claude-opus-4-8" {
		t.Errorf("model = %q", r.Model)
	}
	if r.ConfirmRisk != "high" {
		t.Errorf("confirm_risk = %q, want high", r.ConfirmRisk)
	}
	if r.ConfirmEnabled == nil || !*r.ConfirmEnabled {
		t.Errorf("confirm_enabled = %v, want true", r.ConfirmEnabled)
	}
	if !r.AuditEnabled {
		t.Error("audit_enabled = false, want true")
	}
}

// TestAgentStatus_NoPostureTransport verifies that when the transport
// doesn't expose live posture (Posture nil, e.g. MCP), the handler omits
// read_only rather than reporting a misleading false, and says so.
func TestAgentStatus_NoPostureTransport(t *testing.T) {
	out, err := agentStatusHandler(context.Background(), &Deps{}, nil)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var r agentStatusReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if r.ReadOnly != nil {
		t.Errorf("read_only should be omitted with no posture resolver, got %v", *r.ReadOnly)
	}
	if r.AuditEnabled {
		t.Error("audit_enabled = true with nil Audit, want false")
	}
	joined := strings.Join(r.Notes, " ")
	if !strings.Contains(joined, "not exposed on this transport") {
		t.Errorf("expected a transport note, got %v", r.Notes)
	}
	if !strings.Contains(joined, "audit log is NOT enabled") {
		t.Errorf("expected an audit-disabled note, got %v", r.Notes)
	}
}

// TestAgentStatus_NilDeps is a robustness guard: the handler must not
// panic on a nil Deps (degenerate dispatch).
func TestAgentStatus_NilDeps(t *testing.T) {
	if _, err := agentStatusHandler(context.Background(), nil, nil); err != nil {
		t.Fatalf("nil Deps: %v", err)
	}
}
