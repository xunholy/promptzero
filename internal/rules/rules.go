// Package rules is PromptZero's reactive rules engine. It subscribes to
// the audit observer and fans matching entries out to declarative
// actions: webhook calls, slog lines — and, optionally, agent tool
// invocations when the engine is wired with a runner.
//
// # Design
//
// Each Rule has a Match predicate (AND over non-empty fields) and a list
// of Actions. An Engine owns a registry of rules plus per-rule state
// (enabled flag, last-fire time for cooldown accounting). Engine.Handle
// is the audit observer: it runs every rule's Match, applies cooldown,
// renders the template, and dispatches the actions. Dispatch is
// synchronous from the observer but non-blocking because the underlying
// webhook layer already queues internally.
//
// The match DSL is deliberately thin — reactive rules are cheap sugar
// on top of the audit stream, not a pipeline runtime. Complex
// transformations belong in a workflow or an external subscriber.
package rules

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/obs"
)

// Match is the AND-over-non-empty predicate applied to an audit.Entry.
// Tool supports a trailing "*" glob so "workflow_*" matches any
// workflow_<name> entry.
type Match struct {
	Tool           string
	Risk           string
	Level          string
	OutputContains string
}

// ActionKind enumerates the built-in action types. "webhook" fires via
// the injected WebhookFire hook, "log" emits a slog line, "tool"
// (optional) runs an agent tool via RunTool.
type ActionKind string

const (
	ActionWebhook ActionKind = "webhook"
	ActionLog     ActionKind = "log"
	ActionTool    ActionKind = "tool"
)

// Action is one step. Fields not relevant to the kind are left zero.
type Action struct {
	Kind    ActionKind
	Webhook string // logical webhook name passed to WebhookFire
	Tool    string // tool name for ActionTool
	Params  map[string]interface{}
}

// Rule is one registered match -> actions binding. Name is unique.
// Cooldown suppresses re-fires within the window; use 0 for no cooldown.
// Enabled defaults true when the rule is registered; flip it via Pause.
type Rule struct {
	Name        string
	Description string
	Match       Match
	Actions     []Action
	Cooldown    time.Duration
	Enabled     bool
}

// Deps are the host-supplied side-effect handlers. Any of them may be
// nil; actions requiring a nil hook are skipped with a slog warning at
// fire time. This keeps the engine usable in tests without webhook
// plumbing.
type Deps struct {
	WebhookFire func(name string, payload map[string]any)
	RunTool     func(ctx context.Context, tool string, params map[string]interface{}) (string, error)
	Now         func() time.Time
}

// Engine holds the rule registry, per-rule cooldown state, and deps.
// All methods are goroutine-safe. Zero value is NOT usable — call New.
type Engine struct {
	deps Deps

	mu       sync.Mutex
	rules    map[string]*Rule
	lastFire map[string]time.Time
	fires    map[string]int // lifetime fire counter per rule (for /rules list)
}

// New builds an Engine with no rules installed.
func New(deps Deps) *Engine {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Engine{
		deps:     deps,
		rules:    make(map[string]*Rule),
		lastFire: make(map[string]time.Time),
		fires:    make(map[string]int),
	}
}

// Register adds or replaces a rule. Re-registering a name resets its
// cooldown and fire counter.
func (e *Engine) Register(r Rule) {
	if r.Name == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := r
	e.rules[r.Name] = &cp
	delete(e.lastFire, r.Name)
	e.fires[r.Name] = 0
}

// Remove drops a rule by name. No-op if absent.
func (e *Engine) Remove(name string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.rules, name)
	delete(e.lastFire, name)
	delete(e.fires, name)
}

// Pause disables the named rule (without removing it).
func (e *Engine) Pause(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rules[name]
	if !ok {
		return false
	}
	r.Enabled = false
	return true
}

// Resume re-enables the named rule and clears its cooldown so the next
// matching entry fires immediately.
func (e *Engine) Resume(name string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	r, ok := e.rules[name]
	if !ok {
		return false
	}
	r.Enabled = true
	delete(e.lastFire, name)
	return true
}

// Snapshot is a read-only view of one rule's state.
type Snapshot struct {
	Name        string
	Description string
	Enabled     bool
	Fires       int
	LastFire    time.Time
}

// List returns the rule registry as a slice of Snapshots, sorted by name.
func (e *Engine) List() []Snapshot {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]Snapshot, 0, len(e.rules))
	for name, r := range e.rules {
		out = append(out, Snapshot{
			Name: name, Description: r.Description,
			Enabled: r.Enabled, Fires: e.fires[name], LastFire: e.lastFire[name],
		})
	}
	// Simple name-order sort without pulling in the sort dep at package level.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Name > out[j].Name; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// Handle is the audit observer. It evaluates every rule against the
// entry, honours cooldown, and dispatches matching rules' actions.
// Dispatch errors are logged but never surface to the caller — the
// audit observer path must not block on them.
func (e *Engine) Handle(entry audit.Entry) {
	e.mu.Lock()
	candidates := make([]*Rule, 0, len(e.rules))
	for _, r := range e.rules {
		if !r.Enabled {
			continue
		}
		if !matches(r.Match, entry) {
			continue
		}
		if r.Cooldown > 0 {
			last := e.lastFire[r.Name]
			if !last.IsZero() && e.deps.Now().Sub(last) < r.Cooldown {
				continue
			}
		}
		e.lastFire[r.Name] = e.deps.Now()
		e.fires[r.Name]++
		candidates = append(candidates, r)
	}
	e.mu.Unlock()

	for _, r := range candidates {
		e.fire(r, entry)
	}
}

// Test renders the actions without side effects and returns the
// substitution output so operators can preview a rule. Used by
// `/rules test`.
func (e *Engine) Test(name string, entry audit.Entry) ([]string, error) {
	e.mu.Lock()
	r, ok := e.rules[name]
	e.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("rule %q not found", name)
	}
	out := make([]string, 0, len(r.Actions))
	for _, a := range r.Actions {
		out = append(out, renderAction(a, entry))
	}
	return out, nil
}

func (e *Engine) fire(r *Rule, entry audit.Entry) {
	payload := entryPayload(entry)
	logger := obs.Default().With("rule", r.Name, "tool", entry.Tool, "trace_id", entry.TraceID)

	for _, a := range r.Actions {
		switch a.Kind {
		case ActionWebhook:
			if e.deps.WebhookFire == nil {
				logger.Warn("rule_action_skipped", "kind", string(a.Kind), "reason", "no webhook dispatcher")
				continue
			}
			e.deps.WebhookFire(a.Webhook, withTemplated(a.Params, payload, entry))
		case ActionLog:
			logger.Info("rule_fired", "message", render(firstString(a.Params, "message"), entry))
		case ActionTool:
			if e.deps.RunTool == nil {
				logger.Warn("rule_action_skipped", "kind", string(a.Kind), "reason", "no tool runner")
				continue
			}
			go func(tool string, params map[string]interface{}) {
				ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
				defer cancel()
				if _, err := e.deps.RunTool(ctx, tool, renderParams(params, entry)); err != nil {
					logger.Warn("rule_tool_failed", "tool", tool, "err", err)
				}
			}(a.Tool, a.Params)
		default:
			logger.Warn("rule_unknown_kind", "kind", string(a.Kind))
		}
	}
}

// matches applies the AND-over-non-empty predicate. Trailing "*" in Tool
// enables prefix matching so "workflow_*" fires for every workflow.
func matches(m Match, e audit.Entry) bool {
	if m.Tool != "" {
		if strings.HasSuffix(m.Tool, "*") {
			prefix := strings.TrimSuffix(m.Tool, "*")
			if !strings.HasPrefix(e.Tool, prefix) {
				return false
			}
		} else if m.Tool != e.Tool {
			return false
		}
	}
	if m.Risk != "" && !strings.EqualFold(m.Risk, e.Risk) {
		return false
	}
	if m.Level != "" && !strings.EqualFold(m.Level, string(e.Level)) {
		return false
	}
	if m.OutputContains != "" && !strings.Contains(e.Output, m.OutputContains) {
		return false
	}
	return true
}

// entryPayload is the canonical audit → map shape rules publish out. Keys
// match the webhook event schema so rule-triggered fires look the same
// on the wire as first-class events.
func entryPayload(e audit.Entry) map[string]any {
	return map[string]any{
		"tool":        e.Tool,
		"risk":        e.Risk,
		"level":       string(e.Level),
		"session_id":  e.SessionID,
		"trace_id":    e.TraceID,
		"success":     e.Success,
		"duration_ms": e.Duration,
		"output":      e.Output,
	}
}

// withTemplated overlays caller params onto the audit payload, rendering
// any string value against the entry. Scalar types (numbers, bools)
// pass through unchanged.
func withTemplated(params map[string]interface{}, payload map[string]any, e audit.Entry) map[string]any {
	out := make(map[string]any, len(payload)+len(params))
	for k, v := range payload {
		out[k] = v
	}
	for k, v := range params {
		if s, ok := v.(string); ok {
			out[k] = render(s, e)
		} else {
			out[k] = v
		}
	}
	return out
}

func renderParams(params map[string]interface{}, e audit.Entry) map[string]interface{} {
	out := make(map[string]interface{}, len(params))
	for k, v := range params {
		if s, ok := v.(string); ok {
			out[k] = render(s, e)
		} else {
			out[k] = v
		}
	}
	return out
}

// render substitutes {{tool}}, {{risk}}, {{level}}, {{output}},
// {{session_id}}, {{trace_id}} placeholders against the entry.
func render(tpl string, e audit.Entry) string {
	if tpl == "" {
		return ""
	}
	repl := strings.NewReplacer(
		"{{tool}}", e.Tool,
		"{{risk}}", e.Risk,
		"{{level}}", string(e.Level),
		"{{output}}", e.Output,
		"{{session_id}}", e.SessionID,
		"{{trace_id}}", e.TraceID,
	)
	return repl.Replace(tpl)
}

func renderAction(a Action, e audit.Entry) string {
	switch a.Kind {
	case ActionWebhook:
		return fmt.Sprintf("webhook %q → %v", a.Webhook, withTemplated(a.Params, entryPayload(e), e))
	case ActionLog:
		return fmt.Sprintf("log: %s", render(firstString(a.Params, "message"), e))
	case ActionTool:
		return fmt.Sprintf("tool %s params=%v", a.Tool, renderParams(a.Params, e))
	}
	return string(a.Kind)
}

func firstString(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// slog.Logger check — compile-time reminder that Default() returns a
// logger we actually use; keep the import real even under aggressive
// trimming.
var _ = slog.LevelInfo
