package agent

import (
	"testing"

	"github.com/xunholy/promptzero/internal/cost"
	"github.com/xunholy/promptzero/internal/persona"
)

// TestDefaultModelsByTier_HaveCostRates guards the agent↔cost invariant:
// every model the agent routes to by default must have a pricing row in
// cost.DefaultRates. An unknown model resolves to a zero rate, so the
// cost tracker would silently report $0 for that tier (and budget
// warn/hit thresholds would never fire on it). This catches the easy
// mistake of bumping a model generation in defaultModelsByTier while
// forgetting to add its rate to internal/cost — exactly the pairing the
// v0.736.0 Opus 4.8 bump had to keep in sync by hand.
func TestDefaultModelsByTier_HaveCostRates(t *testing.T) {
	p := cost.NewPricer(nil)
	for tier, model := range defaultModelsByTier {
		if model == "" {
			continue
		}
		if _, ok := p.Rate(model); !ok {
			t.Errorf("tier %q routes to %q, which has no cost.DefaultRates row "+
				"(would track as $0); add it to internal/cost", tier, model)
		}
	}
}

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

// TestModelFor_NoPersona_UsesTierDefaults locks the v0.20.0 behaviour:
// when no persona is configured, classify-tier work goes to Haiku,
// generate/plan to Sonnet, exploit to Opus. Pre-v0.20.0 every tier
// short-circuited to the base model — which routed every cheap-tier
// call to whatever the operator picked as their main model (almost
// always Opus), an enormous overspend.
//
// Unknown tiers still fall through to the base model so a future
// custom tier ("vision", "research") added by a persona stays safe.
func TestModelFor_NoPersona_UsesTierDefaults(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	cases := map[string]string{
		TierClassify:   "claude-haiku-4-5",
		TierGenerate:   "claude-sonnet-4-6",
		TierPlan:       "claude-sonnet-4-6",
		TierExploit:    "claude-opus-4-8",
		"unknown-tier": "claude-sonnet-4-6", // base model fallback
	}
	for tier, want := range cases {
		if got := a.ModelFor(tier); got != want {
			t.Errorf("ModelFor(%q) = %q, want %q", tier, got, want)
		}
	}
}

func TestModelFor_PersonaOverrideWins(t *testing.T) {
	// A persona's Models map takes absolute precedence — even if the
	// override picks a smaller model than the tier default would.
	p := &persona.Persona{
		Name: "red-team-day",
		Models: map[string]string{
			TierClassify: "claude-haiku-4-5",
			TierGenerate: "claude-haiku-4-5", // deliberately picks small
			TierExploit:  "claude-opus-4-7",
		},
	}
	a := agentForModelTest("claude-sonnet-4-6", p)

	cases := map[string]string{
		TierClassify: "claude-haiku-4-5",  // persona override
		TierGenerate: "claude-haiku-4-5",  // persona override
		TierPlan:     "claude-sonnet-4-6", // tier default (Sonnet)
		TierExploit:  "claude-opus-4-7",   // persona override
		"unknown":    "claude-sonnet-4-6", // base model fallback
	}
	for tier, want := range cases {
		if got := a.ModelFor(tier); got != want {
			t.Errorf("ModelFor(%q) = %q, want %q", tier, got, want)
		}
	}
}

func TestModelFor_EmptyPersonaEntryFallsBack(t *testing.T) {
	// An explicit empty string in the persona map (malformed YAML, user
	// typo) must not silently wedge the session. With v0.20.0 the
	// fallback now hits the tier-default table BEFORE the base model —
	// so an empty TierClassify still resolves to Haiku, the right
	// answer for cheap calls.
	p := &persona.Persona{Models: map[string]string{TierClassify: ""}}
	a := agentForModelTest("claude-sonnet-4-6", p)
	if got := a.ModelFor(TierClassify); got != "claude-haiku-4-5" {
		t.Fatalf("empty map entry should fall back to tier default Haiku; got %q", got)
	}
}
