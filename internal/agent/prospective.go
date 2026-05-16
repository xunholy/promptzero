package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
)

// Prospective reflection (Batch A). Before any critical-risk tool
// fires, a classification-tier pass produces a structured plan
// critique. The critique is appended to the tool_result of the
// parent tool_use when the operator is running autonomously, and
// surfaced in the confirm prompt otherwise.
//
// Complements the existing reflexion-on-error (P0-05, which fires
// only on failure). Two-checkpoint pattern: prospective before,
// reactive after. Cheap — one Haiku call per critical tool, capped
// per turn like reflexion.

// maxProspectivePerTurn caps how many critical tools per user turn
// trigger a prospective check. Same rationale as reflexion — a
// wedged turn mustn't mint an arbitrary Haiku bill.
const maxProspectivePerTurn = 5

// ProspectiveCritique is the structured output of a prospective
// pass. Greppable for downstream consumers (report generator,
// detector engine, future constrained planner). Risk and Confidence
// mirror the VerificationVerdict shape so the eventual dashboard
// stays consistent across checkpoints.
type ProspectiveCritique struct {
	// Risk is the classifier's opinion on whether the proposed
	// tool call is coherent: "ok" / "unclear" / "risky".
	Risk string `json:"risk"`
	// Confidence 0.0-1.0 indicating the classifier's certainty.
	Confidence float64 `json:"confidence"`
	// Concerns enumerates specific issues — wrong frequency, missing
	// prerequisite, scope violation, etc.
	Concerns []string `json:"concerns,omitempty"`
	// Recommendation is a short action hint for the main model when
	// Risk != "ok".
	Recommendation string `json:"recommendation,omitempty"`
}

// prospectiveFunc is the injectable Haiku-backed callback so tests
// can exercise the pre-dispatch pipeline without hitting the SDK.
// Returns the critique JSON string on success, "" on any error —
// a failed critique must never block the main dispatch.
type prospectiveFunc func(ctx context.Context, toolName string, input json.RawMessage) string

// maybeProspectiveReflect is the pure-logic half of prospective
// reflection. Given a per-turn counter and a prospectiveFunc, it
// decides whether to run the check and surfaces the critique as a
// <prospective-critique> block preceding any reflection. Nil fn or
// counter skips cleanly.
//
// Returns the original + optional prospective block; caller merges
// the result into the tool_result stream. Does NOT block the tool
// from running — a critique is advisory, not a gate. Operators who
// want a gate layer it on top of the confirm callback.
//
// The critique JSON's string fields (concerns array,
// recommendation) are populated by the classifier LLM and can
// contain free-form prose that echoes attacker-influenceable
// hardware error text. A literal `</prospective-critique>` inside
// any of those strings would render two close tags with text
// between them — same structural-escape risk as the close-tag
// defense arc (v0.134-v0.137). Apply the same defang: rewrite
// `</prospective-critique>` to `< /prospective-critique>` so the
// wrapper boundary survives.
func maybeProspectiveReflect(
	ctx context.Context,
	toolName string,
	input json.RawMessage,
	output string,
	counter *int,
	fn prospectiveFunc,
) string {
	if counter == nil || *counter >= maxProspectivePerTurn {
		return output
	}
	if fn == nil {
		return output
	}
	critique := fn(ctx, toolName, input)
	if critique == "" {
		return output
	}
	critique = strings.ReplaceAll(critique, "</prospective-critique>", "< /prospective-critique>")
	*counter++
	return "<prospective-critique>" + critique + "</prospective-critique>\n" + output
}

// prospective runs the production classifier pass: one Haiku call
// that inspects the upcoming tool invocation and returns a
// structured risk assessment. On any error (timeout, parse failure,
// model babble) the returned string is empty so the caller falls
// back to unchecked dispatch.
//
// Concurrency contract: the caller MUST hold a.mu. Same contract as
// reflect() and routeGroups() — mutable state access is fenced by
// Run's top-level lock.
func (a *Agent) prospective(ctx context.Context, toolName string, input json.RawMessage) string {
	const system = "You are pre-checking a hardware tool call before it fires against a Flipper Zero + " +
		"ESP32 Marauder. Given the tool name and input JSON, judge whether the call looks coherent for " +
		"the named tool: are the parameters the right shape, is the frequency in a plausible ISM band, " +
		"does the protocol match the bit length, does the path resolve to the expected SD root (/ext/...)? " +
		"Output ONLY a JSON object matching " +
		"{\"risk\":\"ok|unclear|risky\",\"confidence\":0.0-1.0,\"concerns\":[\"...\"],\"recommendation\":\"...\"}. " +
		"'ok' means the call looks reasonable. 'unclear' flags ambiguity (missing context, unknown protocol). " +
		"'risky' flags concrete problems (malformed input, out-of-band frequency, path traversal)."

	model := a.modelForLocked(TierClassify)
	userMsg := fmt.Sprintf("tool: %s\ninput: %s", toolName, string(input))

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 256,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userMsg))},
	})
	if err != nil {
		return ""
	}
	a.fireTierUsage(model, resp.Usage)
	var raw string
	for _, b := range resp.Content {
		if b.Type == "text" {
			raw += b.Text
		}
	}
	// Extract the JSON object using the same brace-depth scanner
	// as the verifier (see verify.go). Prose preambles or markdown
	// fences never leak through.
	return extractJSONObject(strings.TrimSpace(raw))
}
