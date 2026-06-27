package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/risk"
)

// audit.go registers the audit_query, audit_export, audit_stats, and
// explain_last_result tools.
//
// audit_query / audit_export / audit_stats are read-only views of the audit
// log. Both surfaces wire that log — agent mode and MCP mode (the MCP server
// calls SetAuditLog, so Deps.Audit is non-nil there too) — so these three are
// NOT AgentOnly and are reachable from MCP clients as well. Each handler
// short-circuits with a friendly message when Audit is nil, so a surface that
// has not wired a log gets a clean response rather than a nil-deref panic.
//
// explain_last_result stays AgentOnly: it is a persona-narration helper for the
// live agent loop, not a generic audit query, and has no meaning over MCP.

//nolint:gochecknoinits
func init() {
	Register(Spec{
		Name: "audit_query",
		Description: "Query the audit log of tool executions (timestamp, input, output, risk level, " +
			"success/failure). Returns the most recent matches first. Optional filters narrow the result for " +
			"incident review:\n" +
			"- **tool** — substring match on the tool name (e.g. `nfc`, `subghz_transmit`).\n" +
			"- **risk** — exact tier: `low` | `medium` | `high` | `critical`.\n" +
			"- **success** — `true` for successes only, `false` for failures only; omit for either.\n" +
			"- **contains** — substring match on the recorded input OR output.\n" +
			"With no filters it behaves as before (the most recent `limit` entries). Read-only.",
		Schema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"limit":{"type":"integer","description":"Max entries to return (default 20)"},
				"tool":{"type":"string","description":"Substring filter on tool name"},
				"risk":{"type":"string","enum":["low","medium","high","critical"],"description":"Filter to one risk tier"},
				"success":{"type":"boolean","description":"true = successes only, false = failures only; omit for either"},
				"contains":{"type":"string","description":"Substring filter on recorded input or output"}
			}
		}`),
		Required: nil,
		Risk:     risk.Low,
		Group:    GroupMetaAudit,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled", nil
			}
			// Validate the risk filter at the boundary so a typo
			// ("hi") fails loudly instead of silently matching nothing.
			riskFilter := strings.ToLower(strings.TrimSpace(str(p, "risk")))
			switch riskFilter {
			case "", "low", "medium", "high", "critical":
			default:
				return "", fmt.Errorf("audit_query: invalid risk %q (want low|medium|high|critical)", riskFilter)
			}
			// QueryFiltered soft-caps Limit at MaxQueryLimit internally,
			// so an LLM tool call with limit=999999 can't tie up SQLite
			// or flood the tool-result with the whole audit DB.
			f := audit.Filter{
				Tool:     strings.TrimSpace(str(p, "tool")),
				Risk:     riskFilter,
				Contains: strings.TrimSpace(str(p, "contains")),
				Limit:    intOr(p, "limit", 20),
			}
			if v, ok := p["success"].(bool); ok {
				f.Success = &v
			}
			entries, err := d.Audit.QueryFiltered(f)
			if err != nil {
				return "", err
			}
			// Substitute an empty slice for a nil result before
			// marshalling so the LLM always sees a JSON array.
			// json.MarshalIndent on a nil []Entry returns the
			// literal "null", which forces the model to know
			// "null means no entries" rather than just iterating
			// an empty list. Same idiom as the v0.163 audit.Export
			// fix.
			if entries == nil {
				entries = []audit.Entry{}
			}
			data, _ := json.MarshalIndent(entries, "", "  ")
			return string(data), nil
		},
	})

	Register(Spec{
		Name: "audit_export",
		Description: "Export the current session's complete audit log. " +
			"Supports JSON (default) and CSV formats. " +
			"Useful for pentest reports, SIEM ingestion, and compliance documentation.",
		Schema: json.RawMessage(`{"type":"object","properties":{
			"format":{"type":"string","description":"Export format: 'json' (default) or 'csv'. CSV is RFC 4180 compliant, suitable for spreadsheet import or SIEM ingestion.","enum":["json","csv"]}
		}}`),
		Required: nil,
		Risk:     risk.Low,
		Group:    GroupMetaAudit,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled", nil
			}
			if str(p, "format") == "csv" {
				return d.Audit.ExportCSV()
			}
			return d.Audit.Export()
		},
	})

	Register(Spec{
		Name: "audit_stats",
		Description: "Show statistics for the current session: total actions, success rate, " +
			"unique tools used.",
		Schema:   json.RawMessage(`{"type":"object","properties":{}}`),
		Required: nil,
		Risk:     risk.Low,
		Group:    GroupMetaAudit,
		Handler: func(_ context.Context, d *Deps, _ map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled", nil
			}
			return d.Audit.Stats()
		},
	})

	Register(Spec{
		Name: "audit_verify",
		Description: "Verify the **tamper-evidence** of the audit log. Each row is hash-chained onto the " +
			"previous one, so a post-hoc edit, mid-chain deletion, reorder, or forged insert made directly " +
			"against the database (e.g. via the sqlite3 CLI) breaks the chain. Returns whether the chain is " +
			"intact, the row id of the first break if not, counts of verified vs legacy (pre-chain) rows, and " +
			"the current `head_hash` + `hashed_rows`.\n\n" +
			"**Out-of-band anchoring:** save the returned `head_hash` and `hashed_rows` somewhere outside the " +
			"database (git, a remote, paper). Passing them back later as `expect_head_hash` + `expect_hashed_rows` " +
			"additionally detects the two attacks the in-database chain alone cannot: a consistent full-chain " +
			"rewrite (the anchored prefix re-hashes to a different head) and truncation of the newest rows " +
			"(fewer hashed rows than anchored). Provide both anchor params together or neither. Read-only.",
		Schema: json.RawMessage(`{
			"type":"object",
			"properties":{
				"expect_head_hash":{"type":"string","description":"A previously-recorded head_hash to anchor against (with expect_hashed_rows)"},
				"expect_hashed_rows":{"type":"integer","description":"The hashed_rows recorded alongside expect_head_hash"}
			}
		}`),
		Required: nil,
		Risk:     risk.Low,
		Group:    GroupMetaAudit,
		Handler: func(_ context.Context, d *Deps, p map[string]any) (string, error) {
			if d.Audit == nil {
				return "Audit logging not enabled", nil
			}
			expectHash := strings.TrimSpace(str(p, "expect_head_hash"))
			expectRows := intOr(p, "expect_hashed_rows", 0)
			// Both anchor params must travel together; one alone is a usage
			// error rather than a silently-ignored half-anchor.
			if (expectHash == "") != (expectRows == 0) {
				return "", fmt.Errorf("audit_verify: provide both expect_head_hash and expect_hashed_rows, or neither")
			}
			var anchor *audit.CheckpointAnchor
			if expectHash != "" {
				anchor = &audit.CheckpointAnchor{HashedRows: expectRows, HeadHash: expectHash}
			}
			res, err := d.Audit.VerifyChainAgainst(anchor)
			if err != nil {
				return "", err
			}
			out, _ := json.MarshalIndent(res, "", "  ")
			return string(out), nil
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
