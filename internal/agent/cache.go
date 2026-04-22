package agent

import "github.com/anthropics/anthropic-sdk-go"

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

// buildCachedRequestWithThinking is buildCachedRequest plus an
// optional extended-thinking budget. When thinkingBudget > 0, the
// request enables Claude's interleaved thinking mode with that
// budget; MaxTokens is raised to cover the thinking allocation plus
// the response body so the API doesn't reject the request with a
// "thinking budget exceeds max_tokens" error.
//
// Thinking-enabled requests are billed at the standard input-token
// rate for thinking tokens (per Anthropic's pricing), so callers
// should gate this on a tier that actually benefits from extended
// reasoning — plan + exploit, not classify.
func buildCachedRequestWithThinking(model, sysPrompt string, tools []anthropic.ToolUnionParam, history []anthropic.MessageParam, thinkingBudget int64) anthropic.MessageNewParams {
	// Response budget: enough for a final answer + any tool_use
	// blocks the model wants to emit. Scales with the thinking
	// budget so a 16K-thinking plan-tier turn still has 4K of
	// headroom for structured output.
	const responseBudget = 4096
	maxTokens := int64(responseBudget)
	if thinkingBudget > 0 {
		maxTokens = thinkingBudget + responseBudget
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
		params.Thinking = anthropic.ThinkingConfigParamOfEnabled(thinkingBudget)
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
