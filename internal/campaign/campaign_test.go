package campaign

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// stubExecutor drives Runner.Run through canned tool responses keyed
// by tool name. Per-invocation hooks are supported for tests that
// need to observe params or fail a specific call.
type stubExecutor struct {
	responses map[string]string
	errors    map[string]error
	calls     []string
}

func (s *stubExecutor) Run(ctx context.Context, tool string, params map[string]interface{}) (string, error) {
	s.calls = append(s.calls, tool)
	if err, ok := s.errors[tool]; ok {
		return "", err
	}
	if out, ok := s.responses[tool]; ok {
		return out, nil
	}
	return "ok", nil
}

const minimalCampaignYAML = `campaign: eval-mvp
steps:
  - id: first
    tool: wifi_scan_ap
    params:
      duration_seconds: 15
`

const dependentCampaignYAML = `campaign: dep-chain
steps:
  - id: scan
    tool: wifi_scan_ap
  - id: list
    tool: wifi_list_aps
    depends_on: scan
  - id: report
    tool: audit_stats
    depends_on: list
`

const whenCampaignYAML = `campaign: when-branch
steps:
  - id: scan
    tool: wifi_scan_ap
  - id: pmkid
    tool: wifi_sniff_pmkid
    depends_on: scan
    when: contains "PMKID"
`

func TestParseYAML_Valid(t *testing.T) {
	c, err := ParseYAML([]byte(minimalCampaignYAML))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}
	if c.Name != "eval-mvp" {
		t.Errorf("Name = %q", c.Name)
	}
	if len(c.Steps) != 1 {
		t.Fatalf("Steps len = %d, want 1", len(c.Steps))
	}
	if c.Steps[0].Tool != "wifi_scan_ap" {
		t.Errorf("Tool = %q", c.Steps[0].Tool)
	}
}

func TestParseYAML_RejectsMissingName(t *testing.T) {
	_, err := ParseYAML([]byte("steps:\n  - id: x\n    tool: y\n"))
	if err == nil {
		t.Error("missing campaign name should error")
	}
}

func TestParseYAML_RejectsNoSteps(t *testing.T) {
	_, err := ParseYAML([]byte("campaign: empty\n"))
	if err == nil {
		t.Error("missing steps should error")
	}
}

func TestParseYAML_RejectsDuplicateStepID(t *testing.T) {
	yamlDoc := `campaign: dup
steps:
  - id: scan
    tool: a
  - id: scan
    tool: b
`
	_, err := ParseYAML([]byte(yamlDoc))
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("duplicate step id should error: %v", err)
	}
}

func TestParseYAML_RejectsUnresolvedDependency(t *testing.T) {
	yamlDoc := `campaign: broken
steps:
  - id: one
    tool: a
    depends_on: ghost
`
	_, err := ParseYAML([]byte(yamlDoc))
	if err == nil || !strings.Contains(err.Error(), "depends_on") {
		t.Errorf("unresolved depends_on should error: %v", err)
	}
}

func TestParseYAML_RejectsSelfDependency(t *testing.T) {
	yamlDoc := `campaign: self
steps:
  - id: one
    tool: a
    depends_on: one
`
	_, err := ParseYAML([]byte(yamlDoc))
	if err == nil || !strings.Contains(err.Error(), "self-dependency") {
		t.Errorf("self-dependency should error: %v", err)
	}
}

// TestParseYAML_RejectsForwardReference catches a step that depends on
// a step declared later in the file. The Runner iterates in declaration
// order, so a forward reference would always observe a not-yet-run
// predecessor and skip with a misleading "dependency failed" reason.
func TestParseYAML_RejectsForwardReference(t *testing.T) {
	yamlDoc := `campaign: forward
steps:
  - id: first
    tool: a
    depends_on: second
  - id: second
    tool: b
`
	_, err := ParseYAML([]byte(yamlDoc))
	if err == nil {
		t.Fatal("forward reference should error")
	}
	if !strings.Contains(err.Error(), "before this step") {
		t.Errorf("expected forward-reference error message, got: %v", err)
	}
}

// TestParseYAML_RejectsMalformedTimeout catches the silent-fallback
// trap: the Runner's time.ParseDuration check just skipped the
// timeout when it couldn't parse, so "timeout: 30 seconds" (English)
// produced unbounded execution with no warning. Validation now fires
// at parse time so the operator sees the typo.
func TestParseYAML_RejectsMalformedTimeout(t *testing.T) {
	cases := []string{
		"30 seconds", // English instead of Go syntax
		"5",          // missing unit
		"-30s",       // negative
		"0s",         // zero (treated as "no limit" per docs but rejected so non-empty must mean "do enforce")
		"forever",
	}
	for _, bad := range cases {
		t.Run(bad, func(t *testing.T) {
			yamlDoc := fmt.Sprintf(`campaign: t
steps:
  - id: a
    tool: x
    timeout: %q
`, bad)
			_, err := ParseYAML([]byte(yamlDoc))
			if err == nil {
				t.Errorf("timeout=%q should error", bad)
			}
		})
	}
}

// TestParseYAML_AcceptsValidTimeout covers happy-path bookend so a
// future tightening of the rule doesn't break legitimate configs.
func TestParseYAML_AcceptsValidTimeout(t *testing.T) {
	for _, good := range []string{"30s", "2m", "1h", "500ms", "1m30s"} {
		t.Run(good, func(t *testing.T) {
			yamlDoc := fmt.Sprintf(`campaign: t
steps:
  - id: a
    tool: x
    timeout: %q
`, good)
			if _, err := ParseYAML([]byte(yamlDoc)); err != nil {
				t.Errorf("timeout=%q should parse: %v", good, err)
			}
		})
	}
}

// TestParseYAML_RejectsCycle catches A→B→A. The cycle implies at least
// one backward edge in declaration order so the forward-reference check
// trips it regardless of which step crosses the boundary.
func TestParseYAML_RejectsCycle(t *testing.T) {
	yamlDoc := `campaign: cycle
steps:
  - id: a
    tool: x
    depends_on: b
  - id: b
    tool: y
    depends_on: a
`
	_, err := ParseYAML([]byte(yamlDoc))
	if err == nil {
		t.Fatal("cycle should error")
	}
	if !strings.Contains(err.Error(), "before this step") && !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected cycle/order error, got: %v", err)
	}
}

func TestRunner_HappyPath(t *testing.T) {
	c, _ := ParseYAML([]byte(dependentCampaignYAML))
	exec := &stubExecutor{responses: map[string]string{
		"wifi_scan_ap":  "3 APs detected",
		"wifi_list_aps": "AP list: home, guest, office",
		"audit_stats":   "tools: 3",
	}}
	r := NewRunner(exec)
	result := r.Run(context.Background(), c)

	if !result.Succeeded() {
		t.Fatalf("expected all steps to succeed: %+v", result)
	}
	if len(result.StepResults) != 3 {
		t.Fatalf("want 3 step results, got %d", len(result.StepResults))
	}
	if result.StepResults[0].StepID != "scan" {
		t.Errorf("execution order wrong: %+v", result.StepResults)
	}
	// All three tools were invoked exactly once.
	if len(exec.calls) != 3 {
		t.Errorf("want 3 executor calls, got %v", exec.calls)
	}
}

func TestRunner_SkipsOnFailedDependency(t *testing.T) {
	c, _ := ParseYAML([]byte(dependentCampaignYAML))
	exec := &stubExecutor{
		responses: map[string]string{
			"wifi_list_aps": "never reached",
			"audit_stats":   "never reached",
		},
		errors: map[string]error{"wifi_scan_ap": errors.New("radio offline")},
	}
	r := NewRunner(exec)
	result := r.Run(context.Background(), c)

	if result.Succeeded() {
		t.Error("run should not report success when a step failed")
	}
	// Subsequent steps should be skipped, not errored.
	if !result.StepResults[1].Skipped {
		t.Errorf("step after failure should be skipped, got %+v", result.StepResults[1])
	}
	if !result.StepResults[2].Skipped {
		t.Errorf("transitive step should also be skipped, got %+v", result.StepResults[2])
	}
	// The dependent tools must not have been invoked.
	for _, call := range exec.calls {
		if call == "wifi_list_aps" || call == "audit_stats" {
			t.Errorf("tool %s should not have been called after scan failure", call)
		}
	}
}

func TestRunner_WhenClauseGates(t *testing.T) {
	c, _ := ParseYAML([]byte(whenCampaignYAML))
	// Scan output deliberately does NOT contain the needle "PMKID"
	// so the dependent step's when-clause evaluates false.
	exec := &stubExecutor{responses: map[string]string{
		"wifi_scan_ap":     "3 APs detected — open, no credentials",
		"wifi_sniff_pmkid": "should not run",
	}}
	r := NewRunner(exec)
	result := r.Run(context.Background(), c)

	// First step runs, second is skipped because the output doesn't
	// contain "PMKID".
	if !result.StepResults[0].Succeeded() {
		t.Errorf("scan should succeed: %+v", result.StepResults[0])
	}
	if !result.StepResults[1].Skipped {
		t.Errorf("pmkid step should be skipped by when clause, got %+v", result.StepResults[1])
	}
	for _, call := range exec.calls {
		if call == "wifi_sniff_pmkid" {
			t.Error("pmkid tool should not have been invoked")
		}
	}
}

func TestRunner_WhenClauseRunsOnMatch(t *testing.T) {
	c, _ := ParseYAML([]byte(whenCampaignYAML))
	exec := &stubExecutor{responses: map[string]string{
		"wifi_scan_ap":     "scan complete; PMKID available for target",
		"wifi_sniff_pmkid": "captured",
	}}
	r := NewRunner(exec)
	result := r.Run(context.Background(), c)

	if !result.StepResults[1].Succeeded() {
		t.Errorf("pmkid should run when clause matches: %+v", result.StepResults[1])
	}
}

func TestRunner_NoExecutorErrorsCleanly(t *testing.T) {
	c, _ := ParseYAML([]byte(minimalCampaignYAML))
	r := NewRunner(nil)
	result := r.Run(context.Background(), c)
	if result.Err == nil {
		t.Error("nil executor should produce a fatal run error")
	}
	if result.Succeeded() {
		t.Error("run with nil executor cannot succeed")
	}
}

func TestRunner_RespectsCtxCancellation(t *testing.T) {
	yamlDoc := `campaign: long
steps:
  - id: one
    tool: a
  - id: two
    tool: b
    depends_on: one
`
	c, _ := ParseYAML([]byte(yamlDoc))
	exec := &stubExecutor{responses: map[string]string{"a": "ok", "b": "also ok"}}
	r := NewRunner(exec)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately cancelled

	result := r.Run(ctx, c)
	// The first step runs (it doesn't check ctx before executing),
	// but the second step's pre-execution ctx check should trip.
	if len(result.StepResults) == 0 {
		t.Fatal("expected at least one step result")
	}
	hasCtxErr := false
	for _, s := range result.StepResults {
		if s.Err != nil && strings.Contains(s.Err.Error(), "context") {
			hasCtxErr = true
		}
	}
	if !hasCtxErr {
		t.Errorf("expected a step to surface context cancellation: %+v", result.StepResults)
	}
}

func TestEvalWhen(t *testing.T) {
	cases := []struct {
		clause string
		output string
		want   bool
	}{
		{"", "anything", true},
		{"contains \"PMKID\"", "PMKID captured", true},
		{"contains \"PMKID\"", "no capture", false},
		{"contains 'PMKID'", "PMKID captured", true},
		{"length > 0", "x", true},
		{"length > 0", "", false},
		{"length > 0", "   ", false}, // whitespace-only
		{"length == 0", "", true},
		{"length == 0", "x", false},
		{"PMKID", "PMKID captured", true}, // bare substring
		{"PMKID", "no capture", false},

		// Unparseable length clauses must conservatively return true
		// per the docstring's "a typo never silently blocks a step"
		// promise. Pre-fix, "length > 5" fell through to the bare-
		// substring match, which would almost never hit on real tool
		// output and would silently skip the step — the exact failure
		// mode the docstring exists to prevent. The fix detects any
		// "length"-prefixed clause that isn't one of the two
		// supported forms and returns true.
		{"length > 5", "real tool output", true},  // unsupported comparator, falls back to "true"
		{"length != 0", "real tool output", true}, // unsupported operator, falls back to "true"
		{"LENGTH > 0", "x", true},                 // case-insensitive match preserved
	}
	for _, c := range cases {
		if got := evalWhen(c.clause, c.output); got != c.want {
			t.Errorf("evalWhen(%q, %q) = %v, want %v", c.clause, c.output, got, c.want)
		}
	}
}

func TestRunResult_DurationZero(t *testing.T) {
	r := RunResult{}
	if got := r.Duration(); got != 0 {
		t.Errorf("zero-valued RunResult should have zero Duration, got %v", got)
	}
}

// TestDemoCampaign_LoadsAndRuns exercises the shipped
// docs/campaigns/office-recon.yaml as a smoke test for the public
// YAML grammar + the runner contract end-to-end. Uses a stub
// executor so no live Flipper is required — this pins the demo
// campaign against silent schema regressions.
func TestDemoCampaign_LoadsAndRuns(t *testing.T) {
	c, err := Load("../../docs/campaigns/office-recon.yaml")
	if err != nil {
		t.Fatalf("Load demo campaign: %v", err)
	}
	if c.Name != "office-recon" {
		t.Errorf("campaign name = %q", c.Name)
	}
	if len(c.Scope.AuthorizedNetworks) == 0 {
		t.Error("demo campaign should declare authorized networks")
	}
	if len(c.Scope.OutOfScope) == 0 {
		t.Error("demo campaign should declare out-of-scope networks")
	}
	if len(c.Steps) != 3 {
		t.Fatalf("demo campaign steps = %d, want 3", len(c.Steps))
	}
	exec := &stubExecutor{responses: map[string]string{
		"wifi_scan_ap":  "found 3 APs: Corp-Guest, home-2G, other",
		"wifi_list_aps": "formatted AP list",
		"audit_stats":   "tools invoked: 2",
	}}
	r := NewRunner(exec)
	result := r.Run(context.Background(), c)
	if !result.Succeeded() {
		t.Fatalf("demo campaign should succeed: %+v", result.StepResults)
	}
	if len(result.StepResults) != 3 {
		t.Errorf("expected 3 step results, got %d", len(result.StepResults))
	}
}

// TestRunner_CancelsTimedStepContextBeforeNextStep pins the v0.92
// resource-hygiene fix. Pre-fix, the runner used `defer cancel()`
// inside its step loop, so every iteration's timer-context cancel
// accumulated on the defer stack and only fired when Run returned —
// long campaigns with many timed steps built up unbounded pending
// timer goroutines. The fix calls cancel() right after exec.Run
// returns so each step's timer is released immediately.
//
// We assert the behavioural contract: step N's ctx must already be
// cancelled by the time step N+1's exec.Run is invoked. Pre-fix this
// fails because step N's cancel is still deferred.
func TestRunner_CancelsTimedStepContextBeforeNextStep(t *testing.T) {
	const yaml = `campaign: cancel-check
steps:
  - id: a
    tool: tool_a
    timeout: 30s
  - id: b
    tool: tool_b
    timeout: 30s
    depends_on: a
`
	c, err := ParseYAML([]byte(yaml))
	if err != nil {
		t.Fatalf("ParseYAML: %v", err)
	}

	var seenCtxs []context.Context
	exec := &recordingExecutor{
		onRun: func(ctx context.Context, _ string) {
			// If a previous step exists, its ctx must already be
			// cancelled — pre-fix this would be non-nil but still
			// active (defer hasn't fired yet).
			if len(seenCtxs) > 0 {
				prev := seenCtxs[len(seenCtxs)-1]
				if prev.Err() == nil {
					t.Errorf("previous step's ctx still active when next step runs — defer-in-loop leak")
				}
			}
			seenCtxs = append(seenCtxs, ctx)
		},
	}
	r := NewRunner(exec)
	result := r.Run(context.Background(), c)
	if !result.Succeeded() {
		t.Fatalf("campaign should succeed: %+v", result.StepResults)
	}
	if len(seenCtxs) != 2 {
		t.Fatalf("expected 2 captured contexts, got %d", len(seenCtxs))
	}
	// Both contexts must be cancelled after Run completes — defensive
	// check that the second step's cancel also fires (covers the
	// "last iteration" case where defer-vs-immediate makes no
	// observable difference but the contract still holds).
	for i, c := range seenCtxs {
		if c.Err() == nil {
			t.Errorf("step %d ctx not cancelled after Run returned", i)
		}
	}
}

// recordingExecutor lets a test inspect the ctx passed to each Run
// call. onRun is invoked synchronously before the executor responds.
type recordingExecutor struct {
	onRun func(ctx context.Context, tool string)
}

func (r *recordingExecutor) Run(ctx context.Context, tool string, _ map[string]interface{}) (string, error) {
	if r.onRun != nil {
		r.onRun(ctx, tool)
	}
	return "ok", nil
}

// TestParseYAML_RejectsWhenWithoutDependsOn pins the fail-closed fix for the
// inert-gate bug: a `when` clause is evaluated against the predecessor's output,
// so without a depends_on the Runner never reaches the when check and the step
// runs UNCONDITIONALLY. An operator gating a destructive tool with `when:` would
// otherwise get a silently-inert guard. Such a campaign must be rejected at load.
func TestParseYAML_RejectsWhenWithoutDependsOn(t *testing.T) {
	yamlDoc := `campaign: ungated-when
steps:
  - id: scan
    tool: wifi_scan_ap
  - id: gated
    tool: wifi_sniff_pmkid
    when: contains "AUTHORIZED"
`
	_, err := ParseYAML([]byte(yamlDoc))
	if err == nil || !strings.Contains(err.Error(), "when clause requires depends_on") {
		t.Errorf("a when without depends_on must be rejected (else the gate runs unconditionally): %v", err)
	}
}
