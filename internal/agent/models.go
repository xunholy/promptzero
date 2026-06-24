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

// defaultModelsByTier maps every tier to a sensible cost-aware default.
// Pre-v0.20.0 the resolution short-circuited straight to a.model when
// the persona didn't override a tier — which routed every classify-tier
// call (router / reflexion / verifier / detector) to the operator's
// configured base model, almost always Opus. That over-spent 5–20× on
// the cheapest path of every turn.
//
// The new fallback table picks the canonical Anthropic family for each
// tier so a persona with Models == nil still gets correct routing:
//
//	classify → Haiku   (router / reflexion / handoff narrative)
//	generate → Sonnet  (payload synthesis — quality matters, Opus overkill)
//	plan     → Sonnet  (main agent turn — multi-step orchestration)
//	exploit  → Opus    (critical confirmations, high-stakes decisions)
//
// Operators who want different defaults still win — both the persona's
// Models map and the session's base model take precedence over this
// table. The table only fires when nothing more specific is set.
//
// Bumped together when Anthropic releases new generations. As of v0.20.0
// the Claude 4.x family is current.
//
//nolint:gochecknoglobals
var defaultModelsByTier = map[string]string{
	TierClassify: "claude-haiku-4-5",
	TierGenerate: "claude-sonnet-4-6",
	TierPlan:     "claude-sonnet-4-6",
	TierExploit:  "claude-opus-4-8",
}

// ModelFor returns the model name the agent should use for the given
// cost tier. Resolution order:
//  1. The active persona's Models[tier] if present.
//  2. The defaultModelsByTier table for the tier.
//  3. The session's base model (a.model) — final fallback.
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
	if m, ok := defaultModelsByTier[tier]; ok && m != "" {
		return m
	}
	return a.model
}

// ThinkingBudgetFor returns the extended-thinking token budget for
// the given tier. Returns 0 when no budget is configured (thinking
// disabled). Values are clamped to the supported range so a
// misspecified persona always produces a valid request instead of
// surfacing the Anthropic API error to the operator:
//
//   - below 1024 (Anthropic minimum) → raised to 1024.
//   - above maxThinkingBudget (64 Ki tokens, comfortably under every
//     model's output ceiling once added to responseBudget) →
//     clamped to maxThinkingBudget. Pre-v0.161 the docstring claimed
//     these values were "clamped by buildCachedRequest at send time"
//     but the actual code scaled MaxTokens to fit, so a typo'd
//     persona with `thinking: { plan: 1000000000 }` produced a
//     request the API rejected with a cryptic 400.
//
// Takes a.mu briefly.
func (a *Agent) ThinkingBudgetFor(tier string) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.thinkingBudgetForLocked(tier)
}

// thinkingBudgetForLocked is ThinkingBudgetFor without the mutex
// acquisition. Caller must hold a.mu.
func (a *Agent) thinkingBudgetForLocked(tier string) int64 {
	if a.persona == nil || a.persona.Thinking == nil {
		return 0
	}
	budget, ok := a.persona.Thinking[tier]
	if !ok || budget <= 0 {
		return 0
	}
	// Anthropic requires >=1024; nudge smaller values to the floor
	// so a misspecified persona still produces valid requests
	// instead of surfacing the API error to the operator.
	const minBudget int64 = 1024
	if budget < minBudget {
		return minBudget
	}
	// Upper cap: every supported Claude model's output ceiling sits
	// comfortably above 64 Ki tokens, and 64 Ki + responseBudget
	// (4 Ki) is well below the API's MaxTokens limit. A persona
	// asking for a huge thinking budget (operator typo,
	// experimental setting) silently overshooting and producing an
	// opaque 400 from the API is poor UX; clamp here instead.
	const maxBudget int64 = 64 * 1024
	if budget > maxBudget {
		return maxBudget
	}
	return budget
}
