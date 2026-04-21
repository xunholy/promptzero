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
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 4096,
		System: []anthropic.TextBlockParam{{
			Text:         sysPrompt,
			CacheControl: anthropic.CacheControlEphemeralParam{TTL: anthropic.CacheControlEphemeralTTLTTL5m},
		}},
		Messages: history,
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
