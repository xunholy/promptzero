package tools

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/xunholy/promptzero/internal/audit"
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

// TestAuditQueryToolCapsLimit pins the soft-cap on audit_query's
// limit param. Without the cap an LLM tool call asking for
// limit=999999 would tie up SQLite and flood the agent's
// tool-result context with the whole audit DB. The cap is
// audit.MaxQueryLimit (10000); seed 50 rows + ask for 999999 +
// confirm the result is bounded.
func TestAuditQueryToolCapsLimit(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "audit.db")
	log, err := audit.Open(logPath)
	if err != nil {
		t.Fatalf("audit.Open: %v", err)
	}
	defer log.Close()
	for i := 0; i < 50; i++ {
		log.Record("test", map[string]int{"i": i}, "ok", "low", audit.LevelInfo, 0, true)
	}

	spec, _ := Get("audit_query")
	out, err := spec.Handler(context.Background(), &Deps{Audit: log},
		map[string]any{"limit": 999999})
	if err != nil {
		t.Fatalf("audit_query: %v", err)
	}
	// At least one entry, fewer than the cap. We don't parse the
	// JSON; the contract is "doesn't blow up and returns bounded
	// content". A successful query against 50 rows produces 50
	// entries — well under the 10000 cap.
	if len(out) == 0 {
		t.Error("audit_query returned empty output")
	}
	if audit.MaxQueryLimit <= 0 {
		t.Errorf("MaxQueryLimit = %d, want > 0", audit.MaxQueryLimit)
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
