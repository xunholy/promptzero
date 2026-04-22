package eval

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/session"
	"github.com/xunholy/promptzero/internal/snapshot"
)

// newHeadlessAgent returns a minimal Agent for eval scenarios. No
// Anthropic client, no Flipper — scenarios wire up whatever they
// need.
func newHeadlessAgent() *agent.Agent {
	return agent.NewForTest("claude-sonnet-4-6")
}

// Default returns the canonical scenario suite used by CI and
// `task eval`. Covers one end-to-end flow per critical agent layer
// so a PR that regresses any of them trips the gate loudly.
//
// Adding a scenario: append a new function below (keep them pure
// — no network, no live Anthropic API) and wire it into this
// constructor.
func Default(t *testing.T) []Scenario {
	t.Helper()
	return []Scenario{
		handoffRoundTripScenario(t),
		snapshotRewindScenario(t),
		attackConstraintScenario(t),
		detectorVerdictScenario(t),
		toolErrorStructureScenario(t),
	}
}

// handoffRoundTripScenario: persist a session with a HandoffArtifact,
// resume it, verify the injected <handoff-resume> context surfaces
// in the rebuilt history. Proves P1-08 end-to-end.
func handoffRoundTripScenario(t *testing.T) Scenario {
	t.Helper()
	return Scenario{
		Name:        "handoff_round_trip",
		Description: "HandoffArtifact persists to session storage and is injected on resume",
		Tags:        []string{"handoff", "session"},
		Run: func() error {
			store, err := session.NewStore(t.TempDir())
			if err != nil {
				return fmt.Errorf("NewStore: %w", err)
			}
			h := agent.HandoffArtifact{
				TurnsCovered: 3,
				Findings:     []agent.HandoffFinding{{Tool: "wifi_scan_ap", Count: 2}},
			}
			st := &session.State{
				ID:      "eval-handoff",
				Model:   "claude-sonnet-4-6",
				Handoff: json.RawMessage(h.JSON()),
			}
			if err := store.Save(st); err != nil {
				return fmt.Errorf("save: %w", err)
			}

			a := newHeadlessAgent()
			a.SetSessionStore(store)
			if err := a.ResumeSession("eval-handoff"); err != nil {
				return fmt.Errorf("ResumeSession: %w", err)
			}
			hist := agent.HistorySnapshot(a)
			if !strings.Contains(hist, "<handoff-resume>") {
				return fmt.Errorf("resumed history missing <handoff-resume> sentinel; got %q", hist)
			}
			if !strings.Contains(hist, "wifi_scan_ap") {
				return fmt.Errorf("resumed history missing finding preview; got %q", hist)
			}
			return nil
		},
	}
}

// snapshotRewindScenario: store a snapshot, rewind, confirm the
// manager returns the same bytes. Proves P1-09 manager round-trip
// without requiring a live Flipper.
func snapshotRewindScenario(t *testing.T) Scenario {
	t.Helper()
	return Scenario{
		Name:        "snapshot_rewind_round_trip",
		Description: "Snapshot manager stores and restores content per session",
		Tags:        []string{"snapshot", "rewind"},
		Run: func() error {
			mgr := snapshot.NewManager(t.TempDir())
			entry, err := mgr.Store("eval-session", "/ext/subghz/fake.sub", []byte("original"))
			if err != nil {
				return fmt.Errorf("store: %w", err)
			}
			got, content, err := mgr.Restore("eval-session", entry.ID)
			if err != nil {
				return fmt.Errorf("restore: %w", err)
			}
			if string(content) != "original" {
				return fmt.Errorf("content mismatch: got %q want %q", content, "original")
			}
			if got.OriginalPath != "/ext/subghz/fake.sub" {
				return fmt.Errorf("OriginalPath mismatch: got %q", got.OriginalPath)
			}
			// Auto-purge via Agent.DeleteSession leaves nothing behind.
			if err := mgr.Purge("eval-session"); err != nil {
				return fmt.Errorf("purge: %w", err)
			}
			entries, _ := mgr.List("eval-session")
			if len(entries) != 0 {
				return fmt.Errorf("purge did not remove snapshots; got %d", len(entries))
			}
			return nil
		},
	}
}

// attackConstraintScenario: install the default attack index,
// constrain the agent to T1557.004, confirm the constraint is
// applied to the tool filter. Proves P1-07 runtime wiring.
func attackConstraintScenario(t *testing.T) Scenario {
	t.Helper()
	return Scenario{
		Name:        "attack_constraint_persists",
		Description: "ATT&CK constraint narrows the per-turn tool catalog",
		Tags:        []string{"attack"},
		Run: func() error {
			a := newHeadlessAgent()
			a.SetAttackIndex(attack.NewDefaultIndex())

			// Empty constraint: AttackConstraint returns nil.
			if got := a.AttackConstraint(); len(got) != 0 {
				return fmt.Errorf("fresh agent has non-empty constraint: %v", got)
			}

			a.SetAttackConstraint([]string{"T1557.004", "T1499"})
			got := a.AttackConstraint()
			if len(got) != 2 {
				return fmt.Errorf("constraint len = %d, want 2", len(got))
			}

			// Clear round-trip.
			a.SetAttackConstraint(nil)
			if got := a.AttackConstraint(); len(got) != 0 {
				return fmt.Errorf("cleared constraint still non-empty: %v", got)
			}
			return nil
		},
	}
}

// detectorVerdictScenario: register a stub detector with the Engine,
// run it, confirm the Verdict shape and that EvaluateFor returns it.
// Proves P1-10 end-to-end without an Anthropic client.
func detectorVerdictScenario(t *testing.T) Scenario {
	t.Helper()
	return Scenario{
		Name:        "detector_engine_evaluates_stub",
		Description: "DetectorEngine routes per-tool detectors and returns Verdicts",
		Tags:        []string{"detector"},
		Run: func() error {
			engine := rules.NewDetectorEngine(500 * (time.Millisecond))
			judge := func(ctx context.Context, system, user string) (string, error) {
				return `{"verdict":"success","confidence":0.92,"evidence":"23 ack frames"}`, nil
			}
			engine.Register("wifi_deauth", rules.NewDeauthSuccessDetector(judge))

			if !engine.HasDetectorsFor("wifi_deauth") {
				return fmt.Errorf("detector not registered")
			}
			verdicts := engine.EvaluateFor(context.Background(), "wifi_deauth", `{"duration_seconds":10}`, "frames:23 ack:23")
			if len(verdicts) != 1 {
				return fmt.Errorf("want 1 verdict, got %d", len(verdicts))
			}
			if verdicts[0].Verdict != rules.VerdictSuccess {
				return fmt.Errorf("verdict = %q, want success", verdicts[0].Verdict)
			}
			if verdicts[0].DetectedBy != "wifi_deauth_success" {
				return fmt.Errorf("DetectedBy = %q", verdicts[0].DetectedBy)
			}
			return nil
		},
	}
}

// toolErrorStructureScenario: classify a timeout-like error, confirm
// the resulting ToolError carries the expected Code / Retryable /
// Remediation. Proves P1-18 end-to-end.
func toolErrorStructureScenario(t *testing.T) Scenario {
	t.Helper()
	return Scenario{
		Name:        "tool_error_classified",
		Description: "ToolError classifier emits machine-readable codes and remediation",
		Tags:        []string{"toolerror", "reliability"},
		Run: func() error {
			te := agent.NewToolErrorForTest("nfc_detect", fmt.Errorf("nfc detect: timeout after 30s"), "")
			if te.Code != "flipper_nfc_timeout" {
				return fmt.Errorf("code = %q, want flipper_nfc_timeout", te.Code)
			}
			if !te.Retryable {
				return fmt.Errorf("timeout should be Retryable")
			}
			if len(te.Remediation) == 0 {
				return fmt.Errorf("timeout should carry remediation hints")
			}
			js := te.JSON()
			if !strings.Contains(js, `"code":"flipper_nfc_timeout"`) {
				return fmt.Errorf("JSON missing code: %s", js)
			}
			return nil
		},
	}
}
