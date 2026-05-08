package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/audit"
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
			limit := intOr(p, "limit", 20)
			// Soft-cap the limit so an LLM tool call with
			// limit=999999 can't tie up SQLite or flood the
			// agent's tool-result with the whole audit DB. Same
			// ceiling as the REPL's /audit query command.
			if limit > audit.MaxQueryLimit {
				limit = audit.MaxQueryLimit
			}
			entries, err := d.Audit.Query(limit)
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

	Register(Spec{
		Name: "explain_last_result",
		Description: "Returns the most recent audit log entry as a structured summary so " +
			"the agent can explain what just happened in plain language. Optimised for " +
			"the explorer persona — pair with `count` to recap the last few steps for " +
			"a learning-mode walkthrough. The agent should narrate the result in the " +
			"persona's voice rather than dumping the JSON verbatim.",
		Schema: json.RawMessage(`{"type":"object","properties":{
			"count":{"type":"integer","description":"How many recent entries to summarise (default 1, max 5)"}
		}}`),
		Required:  nil,
		Risk:      risk.Low,
		Group:     GroupMetaAudit,
		AgentOnly: true,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled — no actions recorded yet to explain.", nil
			}
			n := intOr(p, "count", 1)
			if n < 1 {
				n = 1
			}
			if n > 5 {
				n = 5
			}
			entries, err := d.Audit.Query(n)
			if err != nil {
				return "", err
			}
			if len(entries) == 0 {
				return "No actions in this session yet — try a tool first, then ask me to explain.", nil
			}
			data, _ := json.MarshalIndent(entries, "", "  ")
			return string(data), nil
		},
	})
}
