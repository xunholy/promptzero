package agent

// Cost tiers consumed by the agent when it needs to pick a model for a
// particular kind of work. Higher tiers are expected to be more
// expensive/capable than lower ones. Tiers are strings rather than
// enums so personas can introduce new ones (e.g. "vision") in YAML
// without a code change.
const (
	// TierClassify is for cheap, short-form work: intent routing, tool-
	// catalog narrowing (P0-04 router), reflection summaries (P0-05).
	// Haiku-class models are expected.
	TierClassify = "classify"

	// TierGenerate is the default tier for payload generation (evil
	// portal HTML, BadUSB DuckyScript, generated .sub/.ir/.nfc files).
	// Sonnet-class models are expected.
	TierGenerate = "generate"

	// TierPlan is the default tier for the main agent turn — tool
	// planning, multi-step orchestration, confirmation framing.
	// Sonnet-class models are expected.
	TierPlan = "plan"

	// TierExploit is reserved for highest-stakes decisions (critical
	// risk tools, confirmation explanations). Opus-class models are
	// expected. PromptZero uses this sparingly because Opus is ~5x the
	// price of Sonnet.
	TierExploit = "exploit"
)

// ModelFor returns the model name the agent should use for the given
// cost tier. Resolution order:
//  1. The active persona's Models[tier] if present.
//  2. The session's base model (a.model).
//
// Unknown tiers fall straight through to the base model so code that
// introduces a new tier name is always safe. The function takes the
// agent mutex for a brief read — callers already holding it can use
// modelForLocked instead.
func (a *Agent) ModelFor(tier string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.modelForLocked(tier)
}

// modelForLocked is ModelFor without the mutex acquisition. Caller must
// hold a.mu.
func (a *Agent) modelForLocked(tier string) string {
	if a.persona != nil && a.persona.Models != nil {
		if m, ok := a.persona.Models[tier]; ok && m != "" {
			return m
		}
	}
	return a.model
}
