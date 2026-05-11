// Package workflows implements composite pentest flows that orchestrate
// several Flipper primitives + LLM reasoning behind a single LLM-callable
// tool. Each workflow is a self-contained Go function that:
//
//   - calls primitives via the shared Deps surface (never re-implementing
//     low-level CLI);
//   - records each sub-step to the audit log at level=action;
//   - honours ctx cancellation (partial JSON result, next_steps indicating
//     the cancellation);
//   - returns a single JSON string with {summary, phases[], next_steps[]}
//     plus workflow-specific fields so the calling LLM can both summarise
//     narratively and drive follow-up actions.
//
// The package deliberately avoids introducing new Flipper CLI primitives —
// if a workflow needs something it cannot compose from existing methods on
// flipper.Flipper / marauder.Marauder, that's a bug in Phase 1 and should
// be surfaced, not papered over here.
package workflows

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/vision"
)

// Deps is the dependency surface workflows can call. Fields may be nil when
// the corresponding subsystem isn't connected; workflows that require a
// nil-able field MUST check and return a friendly error instead of panicking.
type Deps struct {
	Flipper      *flipper.Flipper
	Marauder     *marauder.Marauder // nil unless --wifi is active
	Vision       *vision.Analyzer   // may be nil in non-interactive surfaces
	Audit        *audit.Log         // nil when audit logging disabled
	Generator    *generate.Generator
	GenLLM       provider.Provider // raw LLM access for workflows that need ad-hoc summaries
	Capabilities flipper.Capabilities

	// ConfirmSubtool is an optional hook workflows call before
	// dispatching a High/Critical primitive internally. Returns true
	// to proceed, false to skip the sub-step. Nil disables the
	// additional gate (back-compat with tests and orchestrators that
	// already confirmed the workflow as a whole).
	//
	// Rationale: approving workflow_X once at the agent confirm gate
	// used to silently approve every destructive primitive the
	// workflow chained. This hook re-asks the operator for each such
	// sub-step so an approval of the composite doesn't imply an
	// approval of every radio transmission inside it.
	ConfirmSubtool func(ctx context.Context, tool string, input interface{}, riskLevel string) bool
}

// gateSubtool centralises the ConfirmSubtool check so workflows get a
// one-liner before their risky primitives. Returns true to proceed,
// false when the operator declined (workflow should skip the step
// and surface it in the phase record).
func gateSubtool(ctx context.Context, deps Deps, tool string, input interface{}, riskLevel string) bool {
	if deps.ConfirmSubtool == nil {
		return true
	}
	return deps.ConfirmSubtool(ctx, tool, input, riskLevel)
}

// Workflow is the common signature every composite implements. Params come
// straight from the LLM tool-call payload (map[string]interface{} decoded
// from JSON). The returned string is a JSON-encoded Result.
type Workflow func(ctx context.Context, deps Deps, params map[string]interface{}) (string, error)

// PhaseResult describes one orchestrated sub-step: the primitive called,
// whether it succeeded, how long it took, and the raw output string. The
// LLM reads these to reason about what happened mid-workflow.
type PhaseResult struct {
	Phase     string `json:"phase"`
	Tool      string `json:"tool"`
	Output    string `json:"output"`
	OK        bool   `json:"ok"`
	ElapsedMs int64  `json:"elapsed_ms"`
}

// Result is the JSON envelope every workflow returns. Workflow-specific
// fields live under Extra to keep the top-level shape stable across
// workflows while letting each one surface its own structured data
// (e.g. hashcat_format, i2c_addresses, pmkid_hex).
type Result struct {
	Summary   string                 `json:"summary"`
	Phases    []PhaseResult          `json:"phases"`
	NextSteps []string               `json:"next_steps,omitempty"`
	Extra     map[string]interface{} `json:"-"`
}

// MarshalJSON merges Extra into the top-level object so the LLM sees a
// flat shape (e.g. "pmkid_hex" appears next to "summary", not under
// "extra.pmkid_hex"). Collisions with the stable fields are dropped in
// favour of the stable field.
func (r Result) MarshalJSON() ([]byte, error) {
	base := map[string]interface{}{
		"summary": r.Summary,
		"phases":  r.Phases,
	}
	if len(r.NextSteps) > 0 {
		base["next_steps"] = r.NextSteps
	}
	// Collision-check against the full stable-field name set, not just
	// the keys currently in `base`. Without this, a workflow whose
	// NextSteps is empty but whose Extra carries a "next_steps" key
	// (perhaps a typo, perhaps a sub-workflow proxy) would have that
	// Extra value end up in the top-level "next_steps" slot — the
	// docstring promises stable-field wins, and an empty stable field
	// is still a stable field.
	stableFields := map[string]struct{}{
		"summary":    {},
		"phases":     {},
		"next_steps": {},
	}
	for k, v := range r.Extra {
		if _, reserved := stableFields[k]; reserved {
			continue
		}
		base[k] = v
	}
	return json.MarshalIndent(base, "", "  ")
}

// encode marshals a Result to the JSON string every workflow returns as
// its tool-call output. Any marshal failure falls back to a minimal error
// summary so the LLM always gets valid JSON it can reason over.
func encode(r Result) string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fallback, _ := json.Marshal(map[string]string{
			"summary": "workflow result encode failed: " + err.Error(),
		})
		return string(fallback)
	}
	return string(b)
}

// cancelledResult returns a partial JSON envelope with a "cancelled by
// user" next step. Workflows that loop call this as soon as ctx.Done fires
// so the LLM sees every phase that did run plus why the workflow stopped.
func cancelledResult(summary string, phases []PhaseResult, extra map[string]interface{}) string {
	return encode(Result{
		Summary:   summary + " (cancelled)",
		Phases:    phases,
		NextSteps: []string{"cancelled by user"},
		Extra:     extra,
	})
}

// recordPhase audit-logs a workflow phase at level=action, using a tool
// name of "workflow_<name>:<phase>" so /audit find can filter by either
// the workflow or the specific step. Risk is the classified level of the
// underlying primitive so reports still show the right colour.
func recordPhase(log *audit.Log, workflow string, p PhaseResult, input interface{}, risk string) {
	if log == nil {
		return
	}
	log.Record(
		fmt.Sprintf("workflow_%s:%s", workflow, p.Phase),
		input,
		p.Output,
		risk,
		audit.LevelAction,
		time.Duration(p.ElapsedMs)*time.Millisecond,
		p.OK,
	)
}

// paramInt extracts an integer param with a default, coercing every
// numeric and string representation the value might arrive as: float64
// (json.Unmarshal default — the primary tool-call path), float32, int,
// int32, int64 (Go-native callers and tests that build the param map
// directly without a JSON round-trip), plus numeric strings.
// Mirrors tools.intOr (v0.157) so the workflows package matches the
// arg-helper contract from internal/tools.
func paramInt(p map[string]interface{}, key string, fallback int) int {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case float32:
			return int(n)
		case int:
			return n
		case int32:
			return int(n)
		case int64:
			return int(n)
		case string:
			if n == "" {
				return fallback
			}
			// Best-effort: allow "30" as a number-string.
			var out int
			if _, err := fmt.Sscanf(n, "%d", &out); err == nil {
				return out
			}
		}
	}
	return fallback
}

// paramString extracts a string param, returning "" if missing or of the
// wrong type.
func paramString(p map[string]interface{}, key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// paramBool extracts a boolean param with a default.
func paramBool(p map[string]interface{}, key string, fallback bool) bool {
	if v, ok := p[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return fallback
}

// paramIntList extracts a list of integers from an array param,
// matching the per-element numeric-type set paramInt accepts.
// Missing or wrong-shape returns nil so callers can fall back to
// their own defaults. Mirrors tools.intOr (v0.157).
func paramIntList(p map[string]interface{}, key string) []int {
	v, ok := p[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]int, 0, len(arr))
	for _, item := range arr {
		switch n := item.(type) {
		case float64:
			out = append(out, int(n))
		case float32:
			out = append(out, int(n))
		case int:
			out = append(out, n)
		case int32:
			out = append(out, int(n))
		case int64:
			out = append(out, int(n))
		case string:
			var x int
			if _, err := fmt.Sscanf(n, "%d", &x); err == nil {
				out = append(out, x)
			}
		}
	}
	return out
}

// paramStringList extracts a list of strings from params, nil on absence.
func paramStringList(p map[string]interface{}, key string) []string {
	v, ok := p[key]
	if !ok {
		return nil
	}
	arr, ok := v.([]interface{})
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// clamp keeps v in [lo, hi].
func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// firstLine returns the first non-empty line of s, trimmed, for cases
// where an underlying primitive emits a header line + body and the
// summary only wants the header.
func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if t != "" {
			return t
		}
	}
	return ""
}
