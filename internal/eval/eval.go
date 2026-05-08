// Package eval provides the PromptZero golden evaluation harness
// (roadmap P2-25). Scenarios exercise the top-level agent flows —
// handoff round-trip, snapshot / rewind, ATT&CK constraint, detector
// verdicts, prompt-injection quarantine — against mock Flipper +
// Marauder transports. A scenario pass means the agent glue still
// wires up end-to-end; a fail signals a regression that CI might not
// otherwise catch at the unit-test layer.
//
// The harness is deliberately plain Go: each scenario is a func that
// returns an error (or nil). Runner collects timings + tool-call
// counts + error state per scenario. Cost metrics are computed from
// `cost.Tracker` when the scenario installs one.
//
// Scenarios are also discoverable as Go tests (see
// `scenario_tests.go`) so they run under `go test`, `task test`, and
// CI without a custom binary — the Runner type just gives us a
// structured aggregate when the operator wants a summary.
package eval

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// Scenario is a named integration-level check that exercises one or
// more agent features end-to-end. Run returns nil on success; any
// non-nil error is surfaced as a scenario fail. Description is
// optional operator-facing prose.
type Scenario struct {
	Name        string
	Description string
	// Tags group scenarios so a later filter ("only RF scenarios")
	// can subset a run. Examples: "handoff", "snapshot", "attack",
	// "detector", "quarantine".
	Tags []string
	Run  func() error
}

// Result captures the outcome of one scenario pass.
type Result struct {
	Name     string
	Pass     bool
	Err      error
	Duration time.Duration
	// ToolCalls is optional; scenarios that thread a counter through
	// the mock agent can populate it for a richer summary. Scenarios
	// that don't care leave it zero.
	ToolCalls int
}

// Runner holds a registered set of scenarios and executes them in
// deterministic order. Safe to reuse across calls.
type Runner struct {
	scenarios []Scenario
}

// NewRunner returns an empty Runner.
func NewRunner() *Runner {
	return &Runner{}
}

// Register adds a scenario. Duplicate names are allowed — the Runner
// reports them verbatim — but downstream consumers should prefer
// unique names for clean summaries.
func (r *Runner) Register(s Scenario) *Runner {
	r.scenarios = append(r.scenarios, s)
	return r
}

// RegisterAll is a convenience for batch registration.
func (r *Runner) RegisterAll(scenarios ...Scenario) *Runner {
	for _, s := range scenarios {
		r.Register(s)
	}
	return r
}

// Names returns the registered scenario names in registration order.
func (r *Runner) Names() []string {
	out := make([]string, len(r.scenarios))
	for i, s := range r.scenarios {
		out[i] = s.Name
	}
	return out
}

// Run executes every registered scenario sequentially. Each scenario
// is independent: a panic in one does not abort the rest (the Runner
// recovers and reports the panic as an error).
func (r *Runner) Run() []Result {
	out := make([]Result, 0, len(r.scenarios))
	for _, s := range r.scenarios {
		out = append(out, r.runOne(s))
	}
	return out
}

// RunMatching filters scenarios by tag and runs the subset. Empty
// tag list matches everything. Tags use OR semantics — a scenario
// runs if ANY of its tags matches ANY of the filter tags.
func (r *Runner) RunMatching(tags ...string) []Result {
	if len(tags) == 0 {
		return r.Run()
	}
	want := map[string]bool{}
	for _, t := range tags {
		want[t] = true
	}
	out := make([]Result, 0, len(r.scenarios))
	for _, s := range r.scenarios {
		matched := false
		for _, t := range s.Tags {
			if want[t] {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		out = append(out, r.runOne(s))
	}
	return out
}

// runOne executes a single scenario with panic recovery and timing.
// Uses a named return so the deferred recover can mutate the
// outgoing Result (otherwise the return-value copy happens before
// the defer fires and recovery is invisible to the caller).
func (r *Runner) runOne(s Scenario) (result Result) {
	start := time.Now()
	result = Result{Name: s.Name}

	defer func() {
		if rec := recover(); rec != nil {
			result.Pass = false
			// Include the stack trace so operators reading the eval
			// summary can navigate to the panic site inside the
			// scenario without re-running with GOTRACEBACK=all.
			result.Err = fmt.Errorf("panic: %v\nstack:\n%s", rec, debug.Stack())
		}
		result.Duration = time.Since(start)
	}()

	if s.Run == nil {
		result.Err = fmt.Errorf("scenario has no Run func")
		return result
	}
	err := s.Run()
	if err != nil {
		result.Err = err
		return result
	}
	result.Pass = true
	return result
}

// Summarise renders a compact, human-readable report from a Result
// slice. Two-column table with pass/fail marker, name, duration, and
// error (if any). Grouped by tag when the Runner supplied tags.
//
// The format is stable — external tooling (the `task eval` target)
// can grep on "PASS:" / "FAIL:" prefixes.
func Summarise(results []Result) string {
	if len(results) == 0 {
		return "eval: no scenarios registered\n"
	}

	var b strings.Builder
	passCount := 0
	totalDuration := time.Duration(0)

	// Sort by name so the summary is stable.
	sorted := make([]Result, len(results))
	copy(sorted, results)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })

	for _, r := range sorted {
		marker := "FAIL:"
		if r.Pass {
			marker = "PASS:"
			passCount++
		}
		totalDuration += r.Duration
		fmt.Fprintf(&b, "  %s %-40s %s", marker, r.Name, r.Duration.Round(time.Millisecond))
		if r.ToolCalls > 0 {
			fmt.Fprintf(&b, " (%d tool calls)", r.ToolCalls)
		}
		if r.Err != nil {
			fmt.Fprintf(&b, "  — %v", r.Err)
		}
		b.WriteByte('\n')
	}

	fmt.Fprintf(&b, "\n%d / %d scenarios passed in %s\n",
		passCount, len(results), totalDuration.Round(time.Millisecond))
	return b.String()
}

// AllPassed reports whether every result in the slice is a pass.
// CI gates on this.
func AllPassed(results []Result) bool {
	for _, r := range results {
		if !r.Pass {
			return false
		}
	}
	return true
}
