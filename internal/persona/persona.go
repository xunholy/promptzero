// Package persona implements operator-mode profiles for PromptZero.
//
// Each Persona swaps the agent's system prompt and narrows the tool surface
// to a purpose-fit allowlist. Personas are declared in YAML and loaded from
// ~/.promptzero/personas/*.yaml plus a set of built-ins baked into the
// binary. Switching personas (via the --persona flag or the /persona slash
// command) lets an operator move between distinct mission modes —
// RF recon, badge cloning, hardware reverse-engineering, physical pentests,
// or read-only defensive monitoring — without polluting the LLM's context
// with irrelevant tools.
package persona

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/anthropics/anthropic-sdk-go"
	"gopkg.in/yaml.v3"

	"github.com/xunholy/promptzero/internal/obs"
)

// Persona describes a single operator mode. Name is the switch-key used at
// the CLI and in YAML. SystemPrompt replaces the default agent preamble so
// the LLM frames the session correctly. Tools is an allowlist of tool names
// the persona may invoke — an empty slice means "all tools pass through".
// DefaultRiskThreshold is applied to the agent when non-empty and the user
// has not already overridden the threshold via config or CLI flag.
//
// Models is an optional cost-tier → model-name map. Callers ask the agent
// for the model to use per tier (classify / generate / plan / exploit)
// and get back either the persona's configured model or the session's
// fallback. Designed so recon and intent-routing calls can be served by
// a cheaper/faster Haiku while exploitation-planning stays on Opus — see
// docs/specs/roadmap.md P0-02.
type Persona struct {
	Name                 string            `yaml:"name"`
	Description          string            `yaml:"description"`
	SystemPrompt         string            `yaml:"system_prompt"`
	DefaultRiskThreshold string            `yaml:"default_risk_threshold,omitempty"`
	Models               map[string]string `yaml:"models,omitempty"`

	// Consensus is an optional list of model identifiers used for
	// ensemble voting on critical-risk tool calls (roadmap P3-33).
	// When non-empty, the agent runs the prospective critique once
	// per listed model and treats any disagreement as a hard escalate
	// — surfacing a `<consensus-disagreement>` block to the operator
	// instead of letting the call through. Empty disables ensemble
	// voting; the single-model prospective check still runs.
	//
	// Each entry is a model name resolvable via the agent's per-tier
	// model map, e.g. "claude-haiku-4-5", "claude-sonnet-4-6". Names
	// the agent doesn't recognise are skipped with a warn log so a
	// typo doesn't silently disable the gate.
	Consensus []string `yaml:"consensus,omitempty"`

	// Confidence is per-classifier-surface abstention thresholds in
	// [0.0, 1.0] (roadmap P3-29). Keys are the names declared in
	// internal/confidence (`vision`, `router`); values below the
	// threshold cause the agent to abstain — for vision, surface a
	// clarifying user-facing question; for router, fall back to the
	// full tool catalog instead of acting on a low-confidence
	// narrowing. Empty / absent keys fall back to
	// confidence.DefaultClassifierThreshold (0.5), matching the
	// historical input-grounding default. Out-of-range values are
	// clamped at use-site so a misconfigured persona can't push the
	// agent into always-abstain or never-abstain territory.
	Confidence map[string]float64 `yaml:"confidence,omitempty"`

	// Version is an operator-supplied identifier for this persona
	// snapshot — typically a SemVer string ("1.0.0") or a date
	// ("2026-05-10"). Recorded on every audit row through the
	// per-session persona-context resolver (see internal/audit) so
	// regression analysis and the future fine-tuning data exporter
	// (P3-32) can filter sessions by the exact prompt + tool config
	// the operator was running against. Empty when the operator
	// hasn't versioned their persona yet (the safe default — the
	// audit row records "" and the analyser can group by content
	// hash instead). Roadmap P3-31.
	Version string `yaml:"version,omitempty"`

	// Tools is an optional allowlist of tool names. When non-empty,
	// FilterTools narrows the catalog to just these names so the LLM
	// doesn't see anything else.
	//
	// Layered after the read-only safety rail (--read-only / config
	// read_only: true): read-only is the hard no-write contract,
	// while Tools is a positive allowlist that lets a persona
	// scope the catalog (e.g. a "lecture" persona with only the
	// inspect-and-explain tools). The field was originally slated
	// for retirement in v0.20.0; it survived because allowlist-
	// shape persona scoping is genuinely useful alongside the
	// safety rail rather than redundant with it.
	Tools []string `yaml:"tools"`

	// Provider is an optional per-tier LLM-provider override. Keys
	// match the model tier names (classify / generate / plan /
	// exploit) and values are provider identifiers ("claude", "ollama",
	// "openrouter"). Lets a persona declare a fallback for tiers
	// where Anthropic policy may refuse legitimate offensive work —
	// e.g. set generate: ollama on the physical-pentest persona to
	// route payload synthesis through a local model. Empty map
	// preserves the session's default provider for every tier.
	Provider map[string]string `yaml:"provider,omitempty"`

	// Thinking is an optional per-tier extended-thinking budget in
	// tokens. Keys match the model tier names (classify / generate /
	// plan / exploit). A positive value enables Claude's interleaved
	// thinking mode for that tier — the model allocates up to
	// BudgetTokens on internal reasoning before committing to a
	// response. Budgets must be >=1024 and <MaxTokens; the agent
	// caps them at a safe default when out of range. Absent or zero
	// values leave thinking disabled (the pre-Batch-A behaviour).
	Thinking map[string]int64 `yaml:"thinking,omitempty"`
}

// Registry holds the set of known personas. Built-ins are merged with any
// YAML files found under userDir; user YAML with the same name as a built-in
// wins so operators can override shipped defaults.
//
// All methods are goroutine-safe. Production reads happen from REPL +
// HTTP handler goroutines after Load is called at startup; today
// writes only happen at startup (so the happens-before is established
// by the spawn order), but the mutex here is defensive against future
// hot-reload paths.
type Registry struct {
	mu     sync.RWMutex
	byName map[string]*Persona
}

// NewRegistry returns a Registry populated with built-in personas only.
// Call Load or LoadDir to merge in user-defined personas.
func NewRegistry() *Registry {
	r := &Registry{byName: map[string]*Persona{}}
	for _, p := range builtins() {
		p := p
		r.byName[p.Name] = &p
	}
	return r
}

// Load parses a single YAML file and registers the persona it describes.
// The file must decode into a Persona with a non-empty Name.
func (r *Registry) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	var p Persona
	if err := yaml.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("%s: persona missing required 'name' field", path)
	}
	r.mu.Lock()
	r.byName[p.Name] = &p
	r.mu.Unlock()
	return nil
}

// LoadDir walks dir for *.yaml / *.yml files and Loads each one. Missing
// directories return nil so a fresh install without a personas/ dir is
// treated as "built-ins only" rather than an error.
//
// One malformed file no longer aborts the whole load: previously a single
// bad YAML would lose every other valid persona in the directory, since
// the for-loop returned on first error. Now a per-file failure is logged
// via obs.Default().Warn and the loop continues, matching the resilience
// pattern in session.List / snapshot.List / targetmem.Recent.
func (r *Registry) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.Join(dir, name)
		if err := r.Load(path); err != nil {
			obs.Default().Warn("persona_load_failed", "file", name, "err", err)
			continue
		}
	}
	return nil
}

// Get returns the persona registered under name. The second return is false
// when the name is unknown — callers should not dereference the pointer in
// that case.
func (r *Registry) Get(name string) (*Persona, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byName[name]
	return p, ok
}

// Names returns the sorted list of registered persona names. Suitable for
// rendering a picker or building an error message listing valid choices.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.byName))
	for name := range r.byName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// IsUnrestricted reports whether the persona carries no tool allowlist —
// the empty-Tools case that FilterTools treats as "all tools pass through".
func (p *Persona) IsUnrestricted() bool {
	return len(p.Tools) == 0
}

// FilterTools returns the subset of all whose tool name is present in
// allowlist. An empty (or nil) allowlist is treated as "no restriction" and
// all is returned unchanged. Unknown names in the allowlist are silently
// skipped — a persona referencing a renamed tool shouldn't error out, it
// should just lose that capability until the YAML is updated.
func FilterTools(all []anthropic.ToolUnionParam, allowlist []string) []anthropic.ToolUnionParam {
	if len(allowlist) == 0 {
		return all
	}
	set := make(map[string]struct{}, len(allowlist))
	for _, name := range allowlist {
		set[name] = struct{}{}
	}
	out := make([]anthropic.ToolUnionParam, 0, len(all))
	for _, t := range all {
		if t.OfTool == nil {
			continue
		}
		if _, ok := set[t.OfTool.Name]; ok {
			out = append(out, t)
		}
	}
	return out
}

// UserDir returns the default per-user personas directory
// (~/.promptzero/personas). An error is returned when the home directory
// cannot be resolved.
func UserDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".promptzero", "personas"), nil
}
