// Package confidence provides pre-dispatch heuristic scoring for
// tool-use inputs. The agent uses it to flag tool calls where the
// model has likely guessed a required parameter — empty strings,
// placeholder values, "TODO"/"FIXME" tokens, obvious defaults — so
// the dispatch layer can abstain and ask for clarification instead
// of acting on shaky arguments.
//
// This is separate from the chain-of-verification (verify_build.go /
// verifyPayload): verify runs AFTER a tool produces content, checking
// the output. Confidence runs BEFORE dispatch, checking the input.
// The two cover different failure modes — verify catches "we built
// the wrong thing", confidence catches "we're about to act on
// uncertain inputs".
package confidence

import (
	"strings"
)

// Score is a confidence value in [0.0, 1.0]. 1.0 = fully grounded
// inputs, every required field carries a concrete value. 0.0 = the
// input is unsalvageable (empty required fields, obvious placeholders
// throughout). The default abstention threshold is 0.5; callers
// override via Dispatch.
type Score float64

// Threshold below which dispatch should abstain. Tuned against the
// adversarial eval scenarios; a future golden query set will let us
// re-calibrate without touching the heuristics themselves.
const AbstainThreshold Score = 0.5

// placeholders is the list of tokens that, when appearing as an
// entire parameter value, indicate the model was filling in a blank.
// Case-insensitive. Partial hits (e.g. "TODO: figure out") are caught
// by the prefix check below, not by this set.
var placeholders = map[string]struct{}{
	"":                {},
	"todo":            {},
	"fixme":           {},
	"unknown":         {},
	"tbd":             {},
	"xxx":             {},
	"placeholder":     {},
	"example":         {},
	"your_value_here": {},
	"fill_in":         {},
	"<fill_in>":       {},
	"<placeholder>":   {},
	"null":            {},
	"none":            {},
	"n/a":             {},
	"<unknown>":       {},
}

// suspiciousPrefixes catch values that LOOK filled in but actually
// start with a placeholder marker. "TODO: scan first", "example.com"
// and "fixme - resolve BSSID" all trip this.
var suspiciousPrefixes = []string{
	"todo:", "todo ", "todo-", "todo_",
	"fixme:", "fixme ", "fixme-", "fixme_",
	"example.", "example_",
	"placeholder",
}

// Report captures the outcome of a confidence evaluation.
type Report struct {
	Score       Score
	MissingKeys []string
	WeakKeys    []string // present but placeholder-like
	Reason      string
}

// ShouldAbstain is true when Score is below AbstainThreshold.
func (r Report) ShouldAbstain() bool {
	return r.Score < AbstainThreshold
}

// Evaluate scores tool-input params against the required key list.
// Required keys that are missing or placeholder-like subtract weight
// proportional to their share of the required set. Optional keys are
// not scored — the caller already opted to treat them as optional.
//
// With no required keys, the score is always 1.0 (nothing to fail on).
func Evaluate(params map[string]any, required []string) Report {
	if len(required) == 0 {
		return Report{Score: 1.0}
	}
	var missing, weak []string
	for _, k := range required {
		v, ok := params[k]
		if !ok {
			missing = append(missing, k)
			continue
		}
		if isPlaceholder(v) {
			weak = append(weak, k)
		}
	}
	failed := len(missing) + len(weak)
	score := Score(1.0 - float64(failed)/float64(len(required)))
	if score < 0 {
		score = 0
	}
	return Report{
		Score:       score,
		MissingKeys: missing,
		WeakKeys:    weak,
		Reason:      buildReason(missing, weak),
	}
}

func buildReason(missing, weak []string) string {
	if len(missing) == 0 && len(weak) == 0 {
		return ""
	}
	var parts []string
	if len(missing) > 0 {
		parts = append(parts, "missing required keys: "+strings.Join(missing, ", "))
	}
	if len(weak) > 0 {
		parts = append(parts, "placeholder-like values: "+strings.Join(weak, ", "))
	}
	return strings.Join(parts, "; ")
}

// isPlaceholder reports whether a parameter value looks unfilled.
// Non-string values are trusted (a false boolean, a 0 integer — those
// are valid choices the model actually made).
func isPlaceholder(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(s))
	if _, hit := placeholders[lower]; hit {
		return true
	}
	for _, p := range suspiciousPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}
