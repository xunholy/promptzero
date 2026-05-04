package agent

import (
	"context"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/risk"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

// TestRunTool_BlocksHighRiskWithoutAudit locks the audit RequireOpen gate
// for RunTool. Closes Sec HIGH-1: a campaign-runner / rules-engine
// caller must NOT be able to fire High/Critical tools when the audit
// log is nil. Without this guard, an unattended runner can execute
// destructive tools without any forensic trace.
func TestRunTool_BlocksHighRiskWithoutAudit(t *testing.T) {
	a := NewForTest("test-model")
	// auditLog is nil. A High-risk tool must be refused.

	// Use a real registered High-risk tool name so risk.Classify and
	// the registry agree. wifi_deauth is Critical; subghz_transmit is
	// High in the current registry.
	if _, ok := toolsreg.Get("subghz_transmit"); !ok {
		t.Skip("subghz_transmit not registered in this build")
	}

	out, err := a.RunTool(context.Background(), "subghz_transmit", map[string]interface{}{
		"frequency": 433920000,
	})

	if err == nil {
		t.Fatal("RunTool with nil audit + High risk must return an error")
	}
	if !strings.Contains(out, "audit log not initialized") {
		t.Errorf("error message should mention audit log; got: %s", out)
	}
}

// TestRunTool_GatesHighRiskWithConfirmCb locks that a High-risk tool
// invokes the confirm callback. Without this, RunTool would be a
// silent bypass of the confirmation UX that protects Run().
func TestRunTool_GatesHighRiskWithConfirmCb(t *testing.T) {
	a := NewForTest("test-model")
	a.SetConfirmThreshold(risk.High) // production REPL also gates at High
	dir := t.TempDir()
	auditLog, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer auditLog.Close()
	a.SetAuditLog(auditLog)

	var confirmCalls atomic.Int64
	a.SetConfirmCallback(func(_ context.Context, _ ConfirmRequest) ConfirmResponse {
		confirmCalls.Add(1)
		return ConfirmResponse{Decision: DecisionDeny}
	})

	if _, ok := toolsreg.Get("subghz_transmit"); !ok {
		t.Skip("subghz_transmit not registered")
	}

	out, err := a.RunTool(context.Background(), "subghz_transmit", map[string]interface{}{
		"frequency": 433920000,
	})

	if confirmCalls.Load() != 1 {
		t.Errorf("confirm callback called %d times, want 1", confirmCalls.Load())
	}
	if err == nil {
		t.Fatal("denied confirm must propagate as an error from RunTool")
	}
	if !strings.Contains(out, "denied") {
		t.Errorf("output should describe denial; got: %s", out)
	}
}

// TestRunTool_LowRiskRunsWithoutGate verifies the gate doesn't fire
// for Low/Medium tools — that would be confirmation fatigue and would
// also break compatibility for callers that legitimately drive Low
// tools (audit_query, list_devices) from a campaign or rule.
func TestRunTool_LowRiskRunsWithoutGate(t *testing.T) {
	a := NewForTest("test-model")
	dir := t.TempDir()
	auditLog, err := audit.Open(filepath.Join(dir, "audit.db"))
	if err != nil {
		t.Fatalf("open audit: %v", err)
	}
	defer auditLog.Close()
	a.SetAuditLog(auditLog)

	var confirmCalls atomic.Int64
	a.SetConfirmCallback(func(_ context.Context, _ ConfirmRequest) ConfirmResponse {
		confirmCalls.Add(1)
		return ConfirmResponse{Decision: DecisionApprove}
	})

	if spec, ok := toolsreg.Get("audit_query"); !ok || spec.Risk != risk.Low {
		t.Skip("audit_query not registered or no longer Low risk")
	}

	// audit_query expects a query map; pass a no-op filter.
	_, _ = a.RunTool(context.Background(), "audit_query", map[string]interface{}{
		"limit": float64(1),
	})

	if confirmCalls.Load() != 0 {
		t.Errorf("Low-risk tool should NOT trigger confirm; got %d calls", confirmCalls.Load())
	}
}

// TestRunTool_EmptyName is a smoke check that input validation still
// runs.
func TestRunTool_EmptyName(t *testing.T) {
	a := NewForTest("test-model")
	if _, err := a.RunTool(context.Background(), "", nil); err == nil {
		t.Fatal("empty tool name must return an error")
	}
}
