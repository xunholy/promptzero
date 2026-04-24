package tools

import (
	"context"
	"testing"
)

// TestAuditToolsNilTolerance verifies that audit_query, audit_export, and
// audit_stats return a friendly "not enabled" message (not a panic or error)
// when Deps.Audit is nil. This is the nil-tolerance contract: MCP mode and
// test setups that don't wire an audit log must still get a clean response.
func TestAuditToolsNilTolerance(t *testing.T) {
	ctx := context.Background()
	nilDeps := &Deps{} // Audit is nil

	for _, toolName := range []string{"audit_query", "audit_export", "audit_stats"} {
		t.Run(toolName, func(t *testing.T) {
			spec, ok := Get(toolName)
			if !ok {
				t.Fatalf("tool %q not registered", toolName)
			}
			out, err := spec.Handler(ctx, nilDeps, map[string]any{})
			if err != nil {
				t.Fatalf("%s with nil Audit returned error: %v", toolName, err)
			}
			if out != "Audit logging not enabled" {
				t.Errorf("%s with nil Audit = %q, want %q", toolName, out, "Audit logging not enabled")
			}
		})
	}
}

// TestAuditToolsAgentOnly ensures audit_* specs are marked AgentOnly so the
// MCP adapter skips them.
func TestAuditToolsAgentOnly(t *testing.T) {
	for _, toolName := range []string{"audit_query", "audit_export", "audit_stats"} {
		spec, ok := Get(toolName)
		if !ok {
			t.Fatalf("tool %q not registered", toolName)
		}
		if !spec.AgentOnly {
			t.Errorf("%s.AgentOnly = false, want true", toolName)
		}
	}
}
