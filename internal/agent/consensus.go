package agent

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/consensus"
	"github.com/xunholy/promptzero/internal/obs"
)

// Ensemble voting (P3-33). When the active persona declares
// `consensus: [model-a, model-b, …]` AND the about-to-fire tool is
// critical-risk, the agent runs the prospective-critique prompt
// once per listed model and aggregates the verdicts via
// internal/consensus. Disagreement → prepend a structured
// `<consensus-disagreement>` block on the tool result so the model
// stops and surfaces the split to the operator. Unanimity → fall
// through to the existing single-model prospective path.
//
// Implementation notes:
//
//   - Per-call, not per-turn. Critical-risk is rare; we don't worry
//     about a per-turn cap (the existing prospective max-per-turn
//     counter already gates the broader path). Each ensemble call
//     spends one classifier-tier prompt per listed model.
//   - When the call list is empty, returns "" without invoking any
//     model. The dispatcher treats "" as "no escalation".
//   - A single-model failure (timeout, parse error) yields an
//     abstention rather than blocking the whole vote — see the
//     consensus package docs for the rationale.

// runEnsembleProspective fires the prospective critique once per
// model name in `models` and returns the rendered disagreement block
// (or "" on consensus / on no signal at all). Caller MUST hold a.mu.
//
// Returns the empty string when:
//   - models is empty (feature disabled),
//   - the agent has no Anthropic client (test harness),
//   - every model abstains,
//   - or the panel is unanimous.
func (a *Agent) runEnsembleProspective(ctx context.Context, toolName string, input json.RawMessage, models []string) string {
	if len(models) == 0 || a.client == nil {
		return ""
	}
	verdicts := make([]consensus.Verdict, 0, len(models))
	for _, m := range models {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		critique := a.prospectiveWithModel(ctx, toolName, input, m)
		risk := extractRiskFromCritique(critique)
		verdicts = append(verdicts, consensus.Verdict{
			Model:    m,
			Risk:     risk,
			Critique: critique,
		})
	}
	r := consensus.Vote(verdicts)
	if r.Unanimous {
		return ""
	}
	msg := consensus.DisagreementMessage(r)
	if msg != "" {
		obs.FromCtx(ctx).Warn("ensemble_consensus_disagreement",
			"tool", toolName,
			"models", strings.Join(models, ","),
			"abstentions", r.Abstentions)
	}
	return msg
}

// prospectiveWithModel is the explicit-model variant of prospective().
// Where prospective() picks the model from the persona's classify
// tier, this one runs against the caller-supplied model. Used by
// runEnsembleProspective to drive the per-model loop.
//
// On any error (timeout, parse, model babble) returns "" so the
// caller treats this voter as an abstention, matching the single-
// model prospective fail-open posture.
func (a *Agent) prospectiveWithModel(ctx context.Context, toolName string, input json.RawMessage, model string) string {
	const system = "You are pre-checking a hardware tool call before it fires against a Flipper Zero + " +
		"ESP32 Marauder. Given the tool name and input JSON, judge whether the call looks coherent for " +
		"the named tool: are the parameters the right shape, is the frequency in a plausible ISM band, " +
		"does the protocol match the bit length, does the path resolve to the expected SD root (/ext/...)? " +
		"Output ONLY a JSON object matching " +
		"{\"risk\":\"ok|unclear|risky\",\"confidence\":0.0-1.0,\"concerns\":[\"...\"],\"recommendation\":\"...\"}. " +
		"'ok' means the call looks reasonable. 'unclear' flags ambiguity (missing context, unknown protocol). " +
		"'risky' flags concrete problems (malformed input, out-of-band frequency, path traversal)."

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 256,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(
				"tool: " + toolName + "\ninput: " + string(input))),
		},
	})
	if err != nil {
		// The Persona.Consensus docstring promises "Names the agent
		// doesn't recognise are skipped with a warn log so a typo
		// doesn't silently disable the gate." Pre-fix the API error
		// was dropped silently and the operator never learned that
		// `consensus: [calude-sonnet-4-6]` (typo) was effectively
		// abstaining on every critical-risk call. Logging the model
		// + error preserves the safe-abstention semantics while
		// surfacing the cause. Single-model prospective() makes no
		// such promise and stays quiet by design.
		obs.FromCtx(ctx).Warn("ensemble_voter_api_error",
			"tool", toolName,
			"model", model,
			"err", err.Error(),
		)
		return ""
	}
	a.fireTierUsage(model, resp.Usage)
	var raw string
	for _, b := range resp.Content {
		if b.Type == "text" {
			raw += b.Text
		}
	}
	return extractJSONObject(strings.TrimSpace(raw))
}

// extractRiskFromCritique parses a critique JSON object and returns
// the `risk` field's value. Returns "" on any parse failure or
// when the field is absent — the consensus package treats "" as
// abstention.
func extractRiskFromCritique(critique string) string {
	if critique == "" {
		return ""
	}
	var obj struct {
		Risk string `json:"risk"`
	}
	if err := json.Unmarshal([]byte(critique), &obj); err != nil {
		return ""
	}
	return obj.Risk
}
