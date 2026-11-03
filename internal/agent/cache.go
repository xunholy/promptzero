package agent

import "github.com/anthropics/anthropic-sdk-go/v2"

// buildCachedRequest assembles the MessageNewParams sent to Claude and
// installs cache-control breakpoints on the system prompt and the tool
// catalog.
//
// Anthropic prompt caching:
//   - Cache breakpoints mark the tail of a prefix that should be cached
//     for ~5 minutes.
//   - Every request re-sends the full prompt, but tokens before an
//     unchanged breakpoint are billed at ~10 % of the normal rate and
//     skip model re-ingestion, yielding a large latency drop on cache
//     hits.
//
// PromptZero layout:
//   - The system prompt is fully static per (persona, WiFi, workflows)
//     combination — attach a breakpoint there.
//   - The tool catalog is fully static per turn — attach a second
//     breakpoint on the last tool so the whole tool block is cached
//     together with the system prompt.
//   - Conversation history and any injected <device-state> block come
//     *after* the breakpoints and are deliberately excluded from the
//     cache (they change every turn).
//
// The Anthropic API allows up to 4 cache breakpoints per request; we
// use 2.
func buildCachedRequest(model, sysPrompt string, tools []anthropic.ToolUnionParam, history []anthropic.MessageParam) anthropic.MessageNewParams {
	return buildCachedRequestWithThinking(model, sysPrompt, tools, history, 0)
}

// buildCachedRequestWithThinking is buildCachedRequest plus optional
// extended thinking. When thinkingBudget > 0 the request runs Claude's
// adaptive thinking mode with an effort level mapped from the persona's
// legacy per-tier token budget (see effortForBudget).
//
// The Claude 5.x family replaced the fixed budget_tokens knob with
// adaptive thinking + output effort: a budget_tokens request is rejected
// with a 400 on every 5.x model. Rather than break the persona
// `thinking:` YAML contract, the historical token budget is translated
// to the nearest effort tier here, so existing personas keep working and
// the model self-allocates its reasoning within MaxTokens.
//
// MaxTokens is raised when thinking is on so adaptive reasoning plus the
// final answer and any tool_use blocks all fit (thinking tokens are
// drawn from MaxTokens). The request is always streamed, so a generous
// ceiling carries no HTTP-timeout risk.
//
// Thinking tokens bill at the standard input/output rate (per Anthropic
// pricing), so callers should gate this on a tier that benefits from
// extended reasoning — plan + exploit, not classify.
func buildCachedRequestWithThinking(model, sysPrompt string, tools []anthropic.ToolUnionParam, history []anthropic.MessageParam, thinkingBudget int64) anthropic.MessageNewParams {
	// Response budget: enough for a final answer + any tool_use blocks
	// the model wants to emit. Raised when thinking is on so adaptive
	// reasoning has room alongside the structured output.
	const responseBudget = 4096
	const thinkingResponseBudget = 32768
	maxTokens := int64(responseBudget)
	if thinkingBudget > 0 {
		maxTokens = thinkingResponseBudget
	}
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: maxTokens,
		System: []anthropic.TextBlockParam{{
			Text:         sysPrompt,
			CacheControl: anthropic.CacheControlEphemeralParam{TTL: anthropic.CacheControlEphemeralTTLTTL5m},
		}},
		Messages: history,
	}
	if thinkingBudget > 0 {
		params.Thinking = anthropic.ThinkingConfigParamUnion{
			OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{},
		}
		params.OutputConfig = anthropic.OutputConfigParam{
			Effort: effortForBudget(thinkingBudget),
		}
	}

	// Attach a second cache breakpoint to the last tool. The SDK's
	// ToolUnionParam is a union wrapper; breakpoints are only meaningful
	// on concrete tools, so we skip unions whose OfTool is nil (defensive
	// — none exist today, but future tool kinds shouldn't crash caching).
	cached := make([]anthropic.ToolUnionParam, len(tools))
	copy(cached, tools)
	for i := len(cached) - 1; i >= 0; i-- {
		if cached[i].OfTool == nil {
			continue
		}
		// OfTool is a pointer into the source slice; clone so attaching
		// CacheControl doesn't mutate the caller's tool catalog.
		clone := *cached[i].OfTool
		clone.CacheControl = anthropic.CacheControlEphemeralParam{TTL: anthropic.CacheControlEphemeralTTLTTL5m}
		cached[i].OfTool = &clone
		break
	}
	params.Tools = cached
	return params
}

// effortForBudget maps a persona's legacy extended-thinking token budget
// (the pre-5.x `thinking:` YAML knob, expressed in tokens and clamped by
// ThinkingBudgetFor to [1024, 65536]) onto the Claude 5.x output-effort
// level that best preserves its intent. The old knob was a hard token
// ceiling; effort is a qualitative depth dial, so the mapping is a
// best-effort translation rather than an exact equivalence:
//
//	<=  8 Ki  → low     (a light reasoning nudge)
//	<= 24 Ki  → medium  (the 5.x default depth)
//	<= 48 Ki  → high    (deliberate multi-step reasoning)
//	>  48 Ki  → xhigh   (maximum practical depth for agentic turns)
//
// `max` is intentionally never auto-selected — it is reserved for
// operators who set it explicitly, since it trades substantial cost for
// marginal gains outside the hardest problems.
func effortForBudget(budget int64) anthropic.OutputConfigEffort {
	switch {
	case budget <= 8*1024:
		return anthropic.OutputConfigEffortLow
	case budget <= 24*1024:
		return anthropic.OutputConfigEffortMedium
	case budget <= 48*1024:
		return anthropic.OutputConfigEffortHigh
	default:
		return anthropic.OutputConfigEffortXhigh
	}
}
