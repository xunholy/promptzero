package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/risk"
)

// audit.go registers the audit_query, audit_export, and audit_stats tools.
// All three are AgentOnly:true — they read from the session audit log which
// is only wired in agent mode (MCP mode's Deps.Audit is nil). Each handler
// short-circuits with a friendly message when Audit is nil so tests and MCP
// callers get a clean response rather than a nil-deref panic.

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "audit_query",
		Description: "Query the audit log. Shows recent tool executions with timestamps, inputs, outputs, " +
			"risk levels, and success/failure status.",
		Schema:    json.RawMessage(`{"type":"object","properties":{"limit":{"type":"integer","description":"Number of entries to return (default 20)"}}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupMetaAudit,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled", nil
			}
			entries, err := d.Audit.Query(intOr(p, "limit", 20))
			if err != nil {
				return "", err
			}
			data, _ := json.MarshalIndent(entries, "", "  ")
			return string(data), nil
		},
	})

	Register(Spec{
		Name: "audit_export",
		Description: "Export the current session's complete audit log as JSON. " +
			"Useful for pentest reports and compliance documentation.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupMetaAudit,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled", nil
			}
			return d.Audit.Export()
		},
	})

	Register(Spec{
		Name: "audit_stats",
		Description: "Show statistics for the current session: total actions, success rate, " +
			"unique tools used.",
		Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupMetaAudit,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled", nil
			}
			return d.Audit.Stats()
		},
	})
}
