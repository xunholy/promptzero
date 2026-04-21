package agent

import (
	"testing"

	"github.com/xunholy/promptzero/internal/persona"
)

// agentForModelTest builds a minimal agent without any SDK / hardware
// dependencies. ModelFor only reads a.mu-protected fields.
func agentForModelTest(base string, p *persona.Persona) *Agent {
	a := &Agent{model: base}
	if p != nil {
		a.persona = p
		a.personaAtomic.Store(p)
	}
	return a
}

func TestModelFor_FallsBackToBaseModel(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	for _, tier := range []string{TierClassify, TierGenerate, TierPlan, TierExploit, "unknown-tier"} {
		if got := a.ModelFor(tier); got != "claude-sonnet-4-6" {
			t.Errorf("ModelFor(%q) = %q, want base model", tier, got)
		}
	}
}

func TestModelFor_PersonaOverrideWins(t *testing.T) {
	p := &persona.Persona{
		Name: "red-team-day",
		Models: map[string]string{
			TierClassify: "claude-haiku-4-5",
			TierExploit:  "claude-opus-4-7",
		},
	}
	a := agentForModelTest("claude-sonnet-4-6", p)

	cases := map[string]string{
		TierClassify: "claude-haiku-4-5",  // persona override
		TierGenerate: "claude-sonnet-4-6", // falls back to base
		TierPlan:     "claude-sonnet-4-6", // falls back to base
		TierExploit:  "claude-opus-4-7",   // persona override
		"unknown":    "claude-sonnet-4-6", // fallback
	}
	for tier, want := range cases {
		if got := a.ModelFor(tier); got != want {
			t.Errorf("ModelFor(%q) = %q, want %q", tier, got, want)
		}
	}
}

func TestModelFor_EmptyPersonaEntryFallsBack(t *testing.T) {
	// An explicit empty string in the map (malformed YAML, user typo)
	// must not silently wedge the session — fall back to the base model.
	p := &persona.Persona{Models: map[string]string{TierClassify: ""}}
	a := agentForModelTest("claude-sonnet-4-6", p)
	if got := a.ModelFor(TierClassify); got != "claude-sonnet-4-6" {
		t.Fatalf("empty map entry should fall back; got %q", got)
	}
}
