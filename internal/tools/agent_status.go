// agent_status.go — a read-only diagnostic that reports the running
// agent's operator-safety posture, so an operator (or the model on their
// behalf) can confirm "am I read-only? what mode / persona am I in?"
// before acting in a sensitive engagement.

package tools

import (
	"context"
	"encoding/json"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(agentStatusSpec)
}

// agentStatusReport is the JSON shape agent_status returns.
type agentStatusReport struct {
	ReadOnly       *bool    `json:"read_only,omitempty"`
	Mode           string   `json:"mode,omitempty"`
	Persona        string   `json:"persona,omitempty"`
	ConfirmRisk    string   `json:"confirm_risk,omitempty"`
	ConfirmEnabled *bool    `json:"confirm_enabled,omitempty"`
	AuditEnabled   bool     `json:"audit_enabled"`
	Model          string   `json:"model,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

var agentStatusSpec = Spec{
	Name: "agent_status",
	Description: "Report the running agent's **operator-safety posture** — a read-only diagnostic for confirming " +
		"the engagement guardrails before acting. Surfaces:\n" +
		"- **read_only** — whether read-only mode is engaged (refuses any tool above Low risk).\n" +
		"- **mode** — the active group profile (standard / recon / intel / stealth / assault).\n" +
		"- **persona** — the active operator persona.\n" +
		"- **confirm_risk** — the risk tier at/above which the interactive confirmation gate fires, and " +
		"**confirm_enabled** — whether such a gate is actually wired (false on non-interactive surfaces).\n" +
		"- **audit_enabled** — whether tool calls are being recorded to the audit log.\n" +
		"- **model** — the configured base Claude model.\n\n" +
		"Use it to answer questions like \"am I in read-only?\", \"will I be prompted before risky actions?\", or " +
		"\"is this session audited?\". The live reading is point-in-time and accurate; if the agent does not " +
		"expose posture on the current transport (e.g. MCP, which governs risk via its consent gate rather than " +
		"read-only mode), that is stated in the notes rather than guessed. Offline, read-only; transmits " +
		"nothing, so it is Low risk.",
	Schema:    json.RawMessage(`{"type":"object","properties":{}}`),
	Required:  nil,
	Risk:      risk.Low,
	Group:     GroupMetaUtil,
	AgentOnly: false,
	Handler:   agentStatusHandler,
}

func agentStatusHandler(_ context.Context, d *Deps, _ map[string]any) (string, error) {
	r := agentStatusReport{AuditEnabled: d != nil && d.Audit != nil}
	if d != nil && d.Config != nil {
		r.Model = d.Config.Model
	}
	if d != nil && d.Posture != nil {
		p := d.Posture()
		ro := p.ReadOnly
		r.ReadOnly = &ro
		r.Mode = p.Mode
		r.Persona = p.Persona
		r.ConfirmRisk = p.ConfirmRisk
		ce := p.ConfirmEnabled
		r.ConfirmEnabled = &ce
		if !ce {
			r.Notes = append(r.Notes,
				"no interactive confirmation gate is wired (non-interactive surface) — tools at or above "+
					"confirm_risk run without prompting; on MCP the consent gate governs instead")
		}
	} else {
		// No live posture on this transport — say so instead of
		// reporting a misleading read_only=false.
		r.Notes = append(r.Notes,
			"live read-only / mode / persona / confirm posture is not exposed on this transport (e.g. MCP, "+
				"where the risk consent gate — PROMPTZERO_MCP_ALLOW_HIGH / PROMPTZERO_MCP_ALLOW_CRITICAL — governs)")
	}
	if !r.AuditEnabled {
		r.Notes = append(r.Notes, "audit log is NOT enabled for this session — tool calls are not being recorded")
	}
	body, _ := json.MarshalIndent(r, "", "  ")
	return string(body), nil
}
