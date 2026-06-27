// SPDX-License-Identifier: AGPL-3.0-or-later

package eval

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/risk"
)

// The scenarios in this file exercise the dispatch-level safety rails
// end-to-end through the real agent gate chain (agent.RunTool runs the
// audit gate, the confirm gate, then the read-only / mode gate before any
// handler). These are the crown-jewel behaviours; they had unit coverage
// in internal/agent but no agent-flow eval scenario, so a regression in
// the integration path could slip past `task eval`. Each scenario asserts
// both the refusal (the rail engages) and the inverse (it does not
// over-block a legitimate low-risk read).
//
// Tool tiers used: subghz_receive is Medium (radio activation, not a pure
// read), subghz_transmit is High, tool_search is Low (offline registry
// search). NewForTest agents have no audit log and no confirm callback, so
// each scenario wires only the rail it is testing.

// readOnlyRefusalScenario proves the read-only rail refuses anything above
// Low risk at dispatch, and does not block a Low-risk read.
func readOnlyRefusalScenario() Scenario {
	return Scenario{
		Name:        "read_only_refuses_non_read",
		Description: "Read-only mode refuses a Medium-risk tool at dispatch but allows a Low-risk read",
		Tags:        []string{"safety", "read-only"},
		Run: func() error {
			a := newHeadlessAgent()
			a.SetReadOnly(true)
			ctx := context.Background()

			// A Medium-risk tool must be refused with the read-only message.
			// Pass valid params so the refusal comes from the read-only rail
			// in dispatch, not from the earlier input-confidence check.
			out, err := a.RunTool(ctx, "subghz_receive", map[string]any{"frequency": 433920000})
			if err == nil {
				return fmt.Errorf("read-only allowed a Medium-risk tool (subghz_receive)")
			}
			if !strings.Contains(strings.ToLower(out), "read-only") {
				return fmt.Errorf("refusal did not cite read-only mode; output=%q", out)
			}

			// A Low-risk read must NOT be blocked by the read-only rail.
			lowOut, _ := a.RunTool(ctx, "tool_search", map[string]any{"query": "wifi"})
			if strings.Contains(strings.ToLower(lowOut), "read-only") {
				return fmt.Errorf("read-only wrongly blocked a Low-risk read (tool_search); output=%q", lowOut)
			}
			return nil
		},
	}
}

// confirmGateScenario proves the interactive confirm gate fires for a tool
// at/above the threshold (and a deny blocks the call), and does not fire
// for a tool below the threshold.
func confirmGateScenario() Scenario {
	return Scenario{
		Name:        "confirm_gate_denies_and_respects_threshold",
		Description: "The confirm gate fires at/above threshold (deny blocks) and stays silent below it",
		Tags:        []string{"safety", "confirm"},
		Run: func() error {
			a := newHeadlessAgent()
			called := false
			a.SetConfirmCallback(func(_ context.Context, _ agent.ConfirmRequest) agent.ConfirmResponse {
				called = true
				return agent.ConfirmResponse{Decision: agent.DecisionDeny}
			})
			ctx := context.Background()

			// At/above threshold: the gate fires and a deny blocks the tool.
			a.SetConfirmThreshold(risk.Medium)
			_, err := a.RunTool(ctx, "subghz_receive", map[string]any{})
			if !called {
				return fmt.Errorf("confirm gate did not fire for a Medium tool at Medium threshold")
			}
			if err == nil || !strings.Contains(err.Error(), "denied") {
				return fmt.Errorf("a denied confirm did not block the tool; err=%v", err)
			}

			// Below threshold: the gate must stay silent.
			called = false
			a.SetConfirmThreshold(risk.High)
			_, _ = a.RunTool(ctx, "tool_search", map[string]any{"query": "wifi"})
			if called {
				return fmt.Errorf("confirm gate fired for a Low-risk tool below the High threshold")
			}
			return nil
		},
	}
}

// auditFailClosedScenario proves the audit gate refuses High-risk actions
// when no audit log is wired (fail-closed), while still allowing Low-risk
// reads.
func auditFailClosedScenario() Scenario {
	return Scenario{
		Name:        "audit_fail_closed_blocks_high_risk",
		Description: "With no audit log, High-risk actions are refused (fail-closed) but Low-risk reads proceed",
		Tags:        []string{"safety", "audit"},
		Run: func() error {
			a := newHeadlessAgent() // NewForTest wires no audit log
			ctx := context.Background()

			// High-risk with no audit log must be refused.
			_, err := a.RunTool(ctx, "subghz_transmit", map[string]any{})
			if err == nil || !strings.Contains(err.Error(), "audit log not initialized") {
				return fmt.Errorf("audit fail-closed did not block a High-risk tool; err=%v", err)
			}

			// A Low-risk read must not be caught by the fail-closed gate.
			if _, err := a.RunTool(ctx, "tool_search", map[string]any{"query": "wifi"}); err != nil &&
				strings.Contains(err.Error(), "audit log not initialized") {
				return fmt.Errorf("audit gate wrongly blocked a Low-risk read; err=%v", err)
			}
			return nil
		},
	}
}

// rfc8392A1ClaimsHex is the RFC 8392 Appendix A.1 example CWT claims set
// (iss/sub/aud/exp/nbf/iat/cti), used to exercise a decoder through the
// agent dispatch path.
const rfc8392A1ClaimsHex = "a70175636f61703a2f2f61732e6578616d706c652e636f6d02656572696b77" +
	"037818636f61703a2f2f6c696768742e6578616d706c652e636f6d041a5612aeb0051a5610d9f0061a5610d9f007420b71"

// auditChainIntegrityScenario proves the tamper-evidence hash chain
// (v0.761/0.762) holds end-to-end through the agent: tools dispatched via
// RunTool record hash-chained rows, the chain verifies, and an out-of-band
// anchor still validates after the chain grows. The unit tests in
// internal/audit drive Record directly; this guards the agent → RecordCtx →
// chain integration that the dispatch path actually uses.
func auditChainIntegrityScenario(t *testing.T) Scenario {
	t.Helper()
	return Scenario{
		Name:        "audit_chain_intact_after_agent_run",
		Description: "Agent-dispatched tool runs build a valid hash-chained audit trail; an out-of-band anchor validates after the chain grows",
		Tags:        []string{"safety", "audit"},
		Run: func() error {
			a := newHeadlessAgent()
			log, err := audit.Open(filepath.Join(t.TempDir(), "audit.db"))
			if err != nil {
				return fmt.Errorf("audit open: %w", err)
			}
			defer log.Close()
			a.SetAuditLog(log)
			ctx := context.Background()

			// Each Low-risk read records a hash-chained row via RunTool → RecordCtx.
			for i := 0; i < 3; i++ {
				if _, err := a.RunTool(ctx, "tool_search", map[string]any{"query": "wifi"}); err != nil {
					return fmt.Errorf("tool run %d: %w", i, err)
				}
			}
			res, err := log.VerifyChain()
			if err != nil {
				return fmt.Errorf("verify chain: %w", err)
			}
			if !res.Valid {
				return fmt.Errorf("agent-written audit chain is not intact: %s", res.Detail)
			}
			if res.HashedRows < 3 {
				return fmt.Errorf("expected >=3 hashed rows from agent runs, got %d", res.HashedRows)
			}

			// Anchor the current state, grow the chain, confirm the anchor
			// still validates the protected prefix.
			anchor := &audit.CheckpointAnchor{HashedRows: res.HashedRows, HeadHash: res.HeadHash}
			if _, err := a.RunTool(ctx, "tool_search", map[string]any{"query": "nfc"}); err != nil {
				return fmt.Errorf("post-anchor run: %w", err)
			}
			res2, err := log.VerifyChainAgainst(anchor)
			if err != nil {
				return fmt.Errorf("verify against anchor: %w", err)
			}
			if !res2.AnchorChecked || !res2.AnchorValid {
				return fmt.Errorf("anchor failed to validate over a grown chain: %s", res2.AnchorDetail)
			}
			return nil
		},
	}
}

// decoderDispatchScenario proves a representative offline decoder is
// dispatchable through agent.RunTool and returns correct structured output —
// guarding the agent-path integration of the decoder tool family (cwt_decode
// stands in for the WebAuthn/COSE/CWT decoders), which otherwise has only
// direct unit coverage.
func decoderDispatchScenario() Scenario {
	return Scenario{
		Name:        "decoder_dispatches_through_agent",
		Description: "cwt_decode (RFC 8392) dispatches through agent.RunTool and returns the decoded claims",
		Tags:        []string{"decoder", "regression"},
		Run: func() error {
			a := newHeadlessAgent() // cwt_decode is Low risk; no audit log required
			out, err := a.RunTool(context.Background(), "cwt_decode", map[string]any{"input": rfc8392A1ClaimsHex})
			if err != nil {
				return fmt.Errorf("cwt_decode dispatch: %w", err)
			}
			if !strings.Contains(out, "coap://as.example.com") {
				return fmt.Errorf("decoder output missing expected issuer claim: %s", out)
			}
			return nil
		},
	}
}
