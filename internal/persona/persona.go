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

	"github.com/anthropics/anthropic-sdk-go"
	"gopkg.in/yaml.v3"
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
	Tools                []string          `yaml:"tools"`
	DefaultRiskThreshold string            `yaml:"default_risk_threshold,omitempty"`
	Models               map[string]string `yaml:"models,omitempty"`
}

// Registry holds the set of known personas. Built-ins are merged with any
// YAML files found under userDir; user YAML with the same name as a built-in
// wins so operators can override shipped defaults.
type Registry struct {
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
	r.byName[p.Name] = &p
	return nil
}

// LoadDir walks dir for *.yaml / *.yml files and Loads each one. Missing
// directories return nil so a fresh install without a personas/ dir is
// treated as "built-ins only" rather than an error.
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
		if err := r.Load(filepath.Join(dir, name)); err != nil {
			return err
		}
	}
	return nil
}

// Get returns the persona registered under name. The second return is false
// when the name is unknown — callers should not dereference the pointer in
// that case.
func (r *Registry) Get(name string) (*Persona, bool) {
	p, ok := r.byName[name]
	return p, ok
}

// Names returns the sorted list of registered persona names. Suitable for
// rendering a picker or building an error message listing valid choices.
func (r *Registry) Names() []string {
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
