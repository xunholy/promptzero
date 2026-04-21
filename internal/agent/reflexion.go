package agent

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/anthropics/anthropic-sdk-go"
)

// maxReflectionsPerTurn caps how many tool failures within a single user
// turn can trigger a reflection call. Reflection adds a Haiku round trip
// (~1 s) per invocation — useful the first time or two, pathological at
// turn 32 of a wedged loop. Three matches the anecdotal "third failure
// is the bad sign" heuristic from the InterCode-CTF reflection study.
const maxReflectionsPerTurn = 3

// reflectFunc is the function signature Run uses to produce a reflection
// after a tool failure. Returning the empty string skips the append —
// useful when the reflector itself errors or times out (a missing
// reflection is preferable to a broken turn).
type reflectFunc func(ctx context.Context, toolName string, input json.RawMessage, output string) string

// maybeAppendReflection is the pure-logic half of the reflexion feature:
// given a per-turn counter and a reflectFn, it decides whether to call
// the reflector and how to merge the result into the tool output.
// Caller must pass a non-nil counter; it is incremented only when an
// actual reflection was produced and appended.
//
// Output merging keeps the original (possibly multi-line) tool output
// intact and appends the reflection inside a <reflection>...</reflection>
// block so the downstream model sees it clearly delimited from the raw
// error.
func maybeAppendReflection(
	ctx context.Context,
	toolName string,
	input json.RawMessage,
	output string,
	reflectionsThisTurn *int,
	reflectFn reflectFunc,
) string {
	if reflectionsThisTurn == nil || *reflectionsThisTurn >= maxReflectionsPerTurn {
		return output
	}
	if reflectFn == nil {
		return output
	}
	r := reflectFn(ctx, toolName, input, output)
	if r == "" {
		return output
	}
	*reflectionsThisTurn++
	return output + "\n\n<reflection>" + r + "</reflection>"
}

// reflect asks a cheap classification-tier model (typically Haiku) to
// diagnose a failed tool call and suggest a next step. Returns the
// model's raw text output, or the empty string if the call errored —
// the reflection is always optional so a reflector failure must not
// propagate into the main turn.
//
// The prompt is deliberately short and structured: hardware-driven
// failures tend to have stereotypical fixes (reposition, reconnect,
// retry with longer timeout, try a different frequency/protocol) and
// Haiku is reliable when the output shape is tightly bounded.
//
// Concurrency contract: the caller MUST hold a.mu. reflect reads
// a.persona (via modelForLocked) and a.client without re-locking — it
// only ever runs from inside Run() today, which holds the mutex for
// the full turn. If this ever gets called from a different path,
// promote to ModelFor (the public, mutex-acquiring wrapper).
func (a *Agent) reflect(ctx context.Context, toolName string, input json.RawMessage, output string) string {
	const system = "You are diagnosing a tool failure for an AI agent controlling a Flipper Zero + ESP32 Marauder. " +
		"Given the tool name, input, and the raw error output, answer in at most 2 short sentences: " +
		"what went wrong, and what the agent should try next. Be specific about device state (reposition, reconnect, " +
		"timeout, frequency, protocol). Do not invent new tool names or fabricate data. No preamble."

	model := a.modelForLocked(TierClassify)
	userText := fmt.Sprintf("tool: %s\ninput: %s\noutput: %s", toolName, string(input), output)

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 256,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userText))},
	})
	if err != nil {
		return ""
	}
	for _, block := range resp.Content {
		if block.Type == "text" && block.Text != "" {
			return block.Text
		}
	}
	return ""
}
