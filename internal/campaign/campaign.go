// Package campaign implements the PromptZero Campaigns feature
// (roadmap P2-19) — declarative, YAML-authored multi-step
// engagement specs that compose the existing agent tool surface.
//
// A campaign file describes scope, an ordered list of steps, and a
// report template. The Runner executes each step against a
// StepExecutor (typically the agent's dispatch path) and emits a
// RunResult that slots cleanly into internal/report for human-
// readable output.
//
// This ships the foundation. Cron scheduling, a web UI, and
// expression-based when-conditions beyond substring containment are
// explicit future work — the types are forward-compatible with
// those additions.
package campaign

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Campaign is the top-level document a campaign YAML decodes into.
// Name, Scope, Schedule, Steps, Report all survive round-trip.
type Campaign struct {
	Name     string       `yaml:"campaign"`
	Scope    Scope        `yaml:"scope,omitempty"`
	Schedule string       `yaml:"schedule,omitempty"`
	Steps    []Step       `yaml:"steps"`
	Report   ReportConfig `yaml:"report,omitempty"`
}

// Scope captures the authorisation envelope the campaign operates
// under. Runner does not enforce scope — it's metadata for the
// report + for human review before kick-off — but the types are
// here so a future Runner.EnforceScope pass can grow without
// reshuffling YAML.
type Scope struct {
	AuthorizedNetworks []string `yaml:"authorized_networks,omitempty"`
	AuthorizedDevices  []string `yaml:"authorized_devices,omitempty"`
	OutOfScope         []string `yaml:"out_of_scope,omitempty"`
}

// Step is one ordered campaign action. Tool is the agent tool name
// (e.g. "wifi_scan_ap"); Params is its JSON-object arguments. When
// a Step has DependsOn, it runs only after the predecessor
// completed successfully; When, if non-empty, gates execution on
// the predecessor's output matching the condition.
type Step struct {
	ID        string                 `yaml:"id"`
	Tool      string                 `yaml:"tool"`
	Params    map[string]interface{} `yaml:"params,omitempty"`
	DependsOn string                 `yaml:"depends_on,omitempty"`
	When      string                 `yaml:"when,omitempty"`
	// Timeout caps per-step execution. Zero means "no limit" and
	// the executor's own timeout policy governs. Example: "30s",
	// "2m".
	Timeout string `yaml:"timeout,omitempty"`
}

// ReportConfig controls how RunResult is summarised. Template is an
// informational label today (the Markdown renderer is the only
// implementation); Signed hints whether the operator wants a cosign
// signature on the final report — wired when the Campaigns runner
// integrates with the release-style signing path.
type ReportConfig struct {
	Template string `yaml:"template,omitempty"`
	Signed   bool   `yaml:"signed,omitempty"`
}

// Load parses a campaign YAML file from disk. Validates presence of
// the `campaign:` name and at least one step. Duplicate step IDs and
// unresolved depends_on references are rejected so invalid files
// fail at load time rather than mid-run.
func Load(path string) (*Campaign, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return ParseYAML(data)
}

// ParseYAML decodes a campaign YAML byte slice and validates the
// cross-step invariants. Exposed separately so tests can exercise
// the validator without filesystem I/O.
func ParseYAML(data []byte) (*Campaign, error) {
	var c Campaign
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse yaml: %w", err)
	}
	if strings.TrimSpace(c.Name) == "" {
		return nil, errors.New("campaign: missing 'campaign' field")
	}
	if len(c.Steps) == 0 {
		return nil, fmt.Errorf("campaign %q: needs at least one step", c.Name)
	}

	seen := make(map[string]bool, len(c.Steps))
	for i, s := range c.Steps {
		if strings.TrimSpace(s.ID) == "" {
			return nil, fmt.Errorf("campaign %q step %d: missing id", c.Name, i)
		}
		if strings.TrimSpace(s.Tool) == "" {
			return nil, fmt.Errorf("campaign %q step %q: missing tool", c.Name, s.ID)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("campaign %q: duplicate step id %q", c.Name, s.ID)
		}
		seen[s.ID] = true
	}
	// Second pass: validate depends_on after all IDs are known.
	stepIdx := make(map[string]int, len(c.Steps))
	for i, s := range c.Steps {
		stepIdx[s.ID] = i
		if s.DependsOn != "" && !seen[s.DependsOn] {
			return nil, fmt.Errorf("campaign %q step %q: depends_on %q not declared", c.Name, s.ID, s.DependsOn)
		}
		if s.DependsOn == s.ID {
			return nil, fmt.Errorf("campaign %q step %q: self-dependency", c.Name, s.ID)
		}
	}

	// Third pass: declaration-order check. The Runner iterates steps in
	// declared order; a step that depends on a successor would always
	// observe a not-yet-run predecessor and skip with a misleading
	// "dependency failed" reason. Forcing forward references catches the
	// authoring mistake at validate-time. Cycles fall out of this check
	// for free: A→B→A means at least one edge points backward in
	// declaration order, so it trips here regardless of which step
	// crosses the boundary.
	for i, s := range c.Steps {
		if s.DependsOn == "" {
			continue
		}
		predIdx := stepIdx[s.DependsOn]
		if predIdx >= i {
			return nil, fmt.Errorf("campaign %q step %q: depends_on %q must be declared before this step (or cycle detected)",
				c.Name, s.ID, s.DependsOn)
		}
	}

	// Fourth pass: validate the optional timeout string parses as a Go
	// duration when present. The Runner's ParseDuration check silently
	// falls back to no-timeout on malformed input, so an operator
	// typing "timeout: 30 seconds" (invalid Go syntax — should be "30s")
	// got unbounded execution with no warning. Failing at parse time
	// surfaces the typo before the step actually runs.
	for _, s := range c.Steps {
		if s.Timeout == "" {
			continue
		}
		d, err := time.ParseDuration(s.Timeout)
		if err != nil {
			return nil, fmt.Errorf("campaign %q step %q: invalid timeout %q (want Go duration like \"30s\" or \"2m\"): %w",
				c.Name, s.ID, s.Timeout, err)
		}
		if d <= 0 {
			return nil, fmt.Errorf("campaign %q step %q: timeout %q must be positive",
				c.Name, s.ID, s.Timeout)
		}
	}
	return &c, nil
}

// StepExecutor is the interface the Runner uses to invoke an agent
// tool. Production wiring passes the agent's dispatch path; tests
// pass a stub. Keeping the interface minimal means a future Web /
// MCP surface can plug its own executor without touching the Runner.
type StepExecutor interface {
	Run(ctx context.Context, tool string, params map[string]interface{}) (output string, err error)
}

// StepResult captures the outcome of one step in a RunResult.
// Skipped fires when a step's When clause evaluated false or its
// DependsOn predecessor failed.
type StepResult struct {
	StepID     string
	Tool       string
	Output     string
	Err        error
	Duration   time.Duration
	Skipped    bool
	SkipReason string
	StartedAt  time.Time
}

// Succeeded reports whether the step ran to completion without error.
func (r StepResult) Succeeded() bool {
	return r.Err == nil && !r.Skipped
}

// RunResult is the outcome of one Runner.Run. Carries the per-step
// log, wall-clock span, and a roll-up pass/fail flag. Designed so a
// future /report template (or the Campaigns runner's own renderer)
// can format it without re-walking individual steps.
type RunResult struct {
	Campaign    string
	StartedAt   time.Time
	EndedAt     time.Time
	StepResults []StepResult
	Err         error // fatal run error (validator, executor panic); per-step errors live on StepResult
}

// Duration is EndedAt - StartedAt when both are set. Useful for
// report hands-on-time calculations.
func (r RunResult) Duration() time.Duration {
	if r.StartedAt.IsZero() || r.EndedAt.IsZero() {
		return 0
	}
	return r.EndedAt.Sub(r.StartedAt)
}

// Succeeded reports whether every step succeeded (or was cleanly
// skipped). False when any step errored.
func (r RunResult) Succeeded() bool {
	if r.Err != nil {
		return false
	}
	for _, s := range r.StepResults {
		if !s.Succeeded() && !s.Skipped {
			return false
		}
	}
	return true
}

// Runner executes a Campaign against a StepExecutor. Safe to reuse
// across multiple Run() calls — no cached state between invocations.
type Runner struct {
	exec StepExecutor
}

// NewRunner constructs a Runner. Nil executor is acceptable at
// construction time but will cause Run to fail fast when invoked.
func NewRunner(exec StepExecutor) *Runner {
	return &Runner{exec: exec}
}

// Run executes every step in order. Steps with DependsOn wait for
// their predecessor to complete; a failed predecessor marks the
// dependent step Skipped with SkipReason="dependency <id> failed".
// When clauses are evaluated against the predecessor's output and
// default to pass when no predecessor is referenced.
//
// Ctx cancellation aborts the run between steps — an in-flight
// executor call observes the same ctx and is expected to honour it.
func (r *Runner) Run(ctx context.Context, c *Campaign) RunResult {
	result := RunResult{
		Campaign:  c.Name,
		StartedAt: time.Now(),
	}
	if r.exec == nil {
		result.Err = errors.New("campaign runner: no executor configured")
		result.EndedAt = time.Now()
		return result
	}

	byID := make(map[string]*StepResult, len(c.Steps))
	for i := range c.Steps {
		step := c.Steps[i]
		stepRes := StepResult{StepID: step.ID, Tool: step.Tool, StartedAt: time.Now()}
		byID[step.ID] = &stepRes

		// Gate on predecessor success.
		if step.DependsOn != "" {
			prev, ok := byID[step.DependsOn]
			if !ok || !prev.Succeeded() {
				stepRes.Skipped = true
				reason := fmt.Sprintf("dependency %q failed", step.DependsOn)
				if prev != nil && prev.Skipped {
					reason = fmt.Sprintf("dependency %q was skipped", step.DependsOn)
				}
				stepRes.SkipReason = reason
				stepRes.Duration = time.Since(stepRes.StartedAt)
				result.StepResults = append(result.StepResults, stepRes)
				continue
			}
			// When clause evaluates against the predecessor's output.
			if step.When != "" && !evalWhen(step.When, prev.Output) {
				stepRes.Skipped = true
				stepRes.SkipReason = fmt.Sprintf("when clause not satisfied: %s", step.When)
				stepRes.Duration = time.Since(stepRes.StartedAt)
				result.StepResults = append(result.StepResults, stepRes)
				continue
			}
		}

		// Honour ctx cancellation between steps.
		if err := ctx.Err(); err != nil {
			stepRes.Err = err
			stepRes.Duration = time.Since(stepRes.StartedAt)
			result.StepResults = append(result.StepResults, stepRes)
			break
		}

		stepCtx := ctx
		var cancel context.CancelFunc
		if step.Timeout != "" {
			if d, err := time.ParseDuration(step.Timeout); err == nil && d > 0 {
				stepCtx, cancel = context.WithTimeout(ctx, d)
			}
		}

		out, err := r.exec.Run(stepCtx, step.Tool, step.Params)
		// Release the per-step timer immediately rather than waiting
		// for function exit — `defer cancel()` inside a for-loop is a
		// known anti-pattern: every iteration's cancel accumulates on
		// the defer stack and the timer context stays alive (held by
		// the closure in defer) until Run returns. Long campaigns with
		// many timed steps would build up unbounded pending cancels.
		// Matches the pattern in rewindSteps which also runs context-
		// per-iteration writes.
		if cancel != nil {
			cancel()
		}
		stepRes.Output = out
		stepRes.Err = err
		stepRes.Duration = time.Since(stepRes.StartedAt)
		result.StepResults = append(result.StepResults, stepRes)
	}

	result.EndedAt = time.Now()
	return result
}

// evalWhen is the MVP when-clause evaluator. Supported syntax:
//
//	<substring>                         — output contains the raw text
//	contains "<substring>"              — explicit substring form
//	length > 0                          — output has any bytes (>= 1)
//	length == 0                         — output is empty
//
// Unknown / unparseable clauses conservatively return true so a
// typo never silently blocks a step. The set is intentionally tiny
// — Campaign YAML authors get deterministic gates without pulling in
// a full expression language.
func evalWhen(clause, output string) bool {
	c := strings.TrimSpace(clause)
	if c == "" {
		return true
	}
	lower := strings.ToLower(c)
	switch {
	case strings.HasPrefix(lower, "length > 0"):
		return len(strings.TrimSpace(output)) > 0
	case strings.HasPrefix(lower, "length == 0"):
		return len(strings.TrimSpace(output)) == 0
	case strings.HasPrefix(lower, "contains"):
		// e.g. contains "pmkid"
		rest := strings.TrimSpace(c[len("contains"):])
		needle := strings.Trim(rest, `"'`)
		if needle == "" {
			return true
		}
		return strings.Contains(output, needle)
	}
	// Bare text: substring match against the trimmed clause.
	return strings.Contains(output, c)
}
