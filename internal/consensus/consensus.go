// Package consensus implements ensemble voting over multi-model risk
// verdicts (roadmap P3-33). The motivating use-case: before a
// critical-risk tool fires (BadUSB execute, SubGHz TX > +10 dBm, BLE
// spam) run a Haiku-class classifier *and* a Sonnet-class classifier;
// require agreement; escalate to the operator on disagreement.
//
// The package is deliberately tiny: it reasons over the *outputs* of
// per-model prospective critiques, not over the model calls
// themselves. Orchestration lives in the agent (which already knows
// how to call its providers and wire the per-tier model map). The
// agent invokes this package once per critical-tool dispatch.
//
// Design notes:
//
//   - Pure logic. No I/O, no Anthropic SDK, no goroutines. Trivially
//     unit-testable.
//   - Risk classifications are normalised to lowercase ASCII. Partial
//     matches are rejected — `risk=ok` and `risk=okay` count as
//     different verdicts.
//   - An empty-Risk verdict is treated as "abstain" (the model
//     failed to produce a parseable critique). If at least one
//     non-abstain verdict exists, abstentions are excluded from the
//     vote — the dissent payload still records them so the operator
//     sees who abstained.
//   - Unanimity is the only "passing" outcome. Two-of-three is not
//     consensus by design; the operator should know about a split.
package consensus

import (
	"strings"
)

// Verdict is one model's risk classification. Model is the provider/
// model identifier ("claude-haiku-4-5"); Risk is the classifier's
// graded judgement (one of `ok`, `unclear`, `risky` as defined by
// internal/agent's ProspectiveCritique). Critique is the raw JSON or
// prose the model returned, preserved so the operator-facing
// disagreement message can show source-of-truth excerpts on each
// path.
type Verdict struct {
	Model    string
	Risk     string
	Critique string
}

// Result is the aggregated decision. Unanimous reports whether every
// non-abstain verdict agreed; AgreedRisk is set only when Unanimous
// is true. Verdicts is always the input list (preserved for
// reporting). Abstentions count is exposed so the operator can see
// when a "Unanimous" outcome was actually a one-vote consensus
// because the rest of the panel abstained.
type Result struct {
	Unanimous   bool
	AgreedRisk  string
	Verdicts    []Verdict
	Abstentions int
}

// Vote tallies a slice of Verdicts.
//
// Outcomes:
//   - 0 verdicts:        Unanimous=false, AgreedRisk="" (no input).
//   - all abstain:       Unanimous=false, AgreedRisk="" (no signal).
//   - one non-abstain:   Unanimous=true, AgreedRisk=that risk
//     (abstentions don't block; a single voter still passes).
//   - multiple agree:    Unanimous=true, AgreedRisk=shared risk.
//   - multiple disagree: Unanimous=false, AgreedRisk="".
func Vote(verdicts []Verdict) Result {
	r := Result{Verdicts: verdicts}
	if len(verdicts) == 0 {
		return r
	}
	var agreed string
	var votes int
	for _, v := range verdicts {
		risk := normaliseRisk(v.Risk)
		if risk == "" {
			r.Abstentions++
			continue
		}
		if votes == 0 {
			agreed = risk
			votes = 1
			continue
		}
		if risk != agreed {
			// Disagreement.
			return r
		}
		votes++
	}
	if votes == 0 {
		return r
	}
	r.Unanimous = true
	r.AgreedRisk = agreed
	return r
}

// DisagreementMessage produces a structured `<consensus-disagreement>`
// block for an agent's tool result when Vote returned Unanimous=false
// AND there are at least two non-abstain dissenting verdicts. Returns
// "" otherwise — the agent is responsible for treating "no message"
// as "no escalation needed".
//
// The block includes one line per non-abstaining verdict so the
// operator can see exactly which model said what. Abstentions are
// reported as a tally rather than per-model lines because they don't
// carry a verdict to compare.
func DisagreementMessage(r Result) string {
	if r.Unanimous || len(r.Verdicts) == 0 {
		return ""
	}
	// Skip the block when the only "dissent" is abstentions on every
	// model — there's no real split to escalate, just no signal.
	nonAbstain := 0
	for _, v := range r.Verdicts {
		if normaliseRisk(v.Risk) != "" {
			nonAbstain++
		}
	}
	if nonAbstain < 2 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<consensus-disagreement>\n")
	b.WriteString("The configured ensemble disagreed on this critical-risk decision. ")
	b.WriteString("Stop and ask the operator before proceeding.\n")
	for _, v := range r.Verdicts {
		risk := normaliseRisk(v.Risk)
		if risk == "" {
			continue
		}
		b.WriteString("- ")
		// Model is operator-supplied from the persona YAML's
		// `consensus:` list and the critique is LLM-generated. Neither
		// is direct attacker-controlled text, but defense in depth
		// mirrors agent.quarantineOutput (v0.134) and
		// breaker.EscalationMessage (v0.135): rewrite any literal
		// `</consensus-disagreement>` inside the embedded strings to
		// `< /consensus-disagreement>` so a smuggled close tag can't
		// terminate the wrapper early.
		b.WriteString(neutralizeCloseTag(v.Model))
		b.WriteString(": ")
		b.WriteString(risk)
		if excerpt := summariseCritique(v.Critique); excerpt != "" {
			b.WriteString(" — ")
			b.WriteString(neutralizeCloseTag(excerpt))
		}
		b.WriteByte('\n')
	}
	if r.Abstentions > 0 {
		writeAbstainTally(&b, r.Abstentions)
	}
	b.WriteString("</consensus-disagreement>")
	return b.String()
}

// neutralizeCloseTag rewrites any literal `</consensus-disagreement>`
// inside the content to `< /consensus-disagreement>`. See
// DisagreementMessage's docstring for the rationale and
// agent.quarantineOutput (v0.134) / breaker.EscalationMessage
// (v0.135) for the parallel patterns.
func neutralizeCloseTag(content string) string {
	return strings.ReplaceAll(content, "</consensus-disagreement>", "< /consensus-disagreement>")
}

// normaliseRisk lowercases + trims a Risk string. Returns "" for
// values that don't match the canonical set so a malformed verdict
// can't masquerade as agreement (e.g. an empty-string risk silently
// matching another empty-string risk and producing a false Unanimous).
func normaliseRisk(r string) string {
	switch strings.ToLower(strings.TrimSpace(r)) {
	case "ok":
		return "ok"
	case "unclear":
		return "unclear"
	case "risky":
		return "risky"
	}
	return ""
}

// summariseCritique returns a short single-line excerpt of a critique
// payload — the first non-empty line, capped at 200 chars. Used to
// render the operator-facing disagreement message without dumping a
// full JSON blob per model.
func summariseCritique(s string) string {
	for _, line := range strings.Split(strings.TrimSpace(s), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(line) > 200 {
			// UTF-8-aware: walk back from a continuation byte
			// (10xxxxxx) so an emoji / accented char straddling
			// byte 200 isn't split into a half-rune that downstream
			// JSON marshaling renders as U+FFFD. Mirrors the same
			// fix in validator/badusb.go (v0.120), rag.Snippet
			// (v0.123), generate.truncate (v0.133), and the audit
			// row truncate.
			cut := 200
			for cut > 0 && line[cut]&0xC0 == 0x80 {
				cut--
			}
			line = line[:cut] + "…"
		}
		return line
	}
	return ""
}

func writeAbstainTally(b *strings.Builder, n int) {
	b.WriteString("(")
	if n == 1 {
		b.WriteString("1 model abstained — no parseable verdict")
	} else {
		// Hand-roll the int formatting for one digit-string so the
		// package keeps a zero-dependency contract.
		b.WriteString(itoa(n))
		b.WriteString(" models abstained — no parseable verdict")
	}
	b.WriteString(")\n")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = byte('0' + n%10)
		n /= 10
	}
	return string(digits[i:])
}
