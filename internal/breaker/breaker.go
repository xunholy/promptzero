// Package breaker implements a per-tool consecutive-error circuit
// breaker (roadmap P3-28, second half). The motivating failure mode
// is the "loader_close infinite loop" called out in the roadmap: a
// tool fails in a particular way, the LLM retries, hits the same
// failure, retries again — and so on, burning tokens without
// progress. After N consecutive same-kind errors on the same tool,
// the breaker trips and the dispatch layer surfaces a structured
// escalation signal so the model sees an explicit "stop hammering
// this; try something different" cue.
//
// Design notes:
//
//   - Per-tool. A fan-out across multiple tools doesn't trip any
//     individual breaker. A failure on tool A followed by a failure
//     on tool B doesn't count as "same kind" — that's diagnostic
//     spread, not stuck.
//   - Same-kind detection is a normalised string comparison on the
//     observed error / output. Different error strings reset the
//     streak. This is intentionally conservative — we'd rather miss
//     a stuck loop with two slightly-different error messages than
//     trip a false positive on a legitimate retry that happens to
//     use the same tool but for a different parameter.
//   - State is process-local. There is no on-disk persistence; an
//     agent restart resets every breaker. That's the right shape for
//     a session-bound REPL.
//   - The breaker reports state but does NOT enforce a hard refusal.
//     The dispatch layer decides what to do with `Open=true`: the
//     usual response is to append a structured marker to the tool
//     output so the model sees the escalation before its next turn.
//     A future iteration could add a hard refuse-the-call mode.
package breaker

import (
	"strings"
	"sync"
)

// DefaultThreshold is the consecutive-same-kind-error count at which
// a breaker trips. Three matches the roadmap's stated "after 3
// consecutive same-kind errors, escalate".
const DefaultThreshold = 3

// Counter tracks per-tool consecutive same-kind failures. The zero
// value is NOT usable — call New. Counter is safe for concurrent use.
type Counter struct {
	threshold int

	mu     sync.Mutex
	tools  map[string]*toolState
	totals stats
}

// State is a snapshot of one tool's breaker state, returned by
// Record so callers can decide what to do with the new state without
// re-locking.
type State struct {
	// Tool name this state is for.
	Tool string
	// LastKind is the normalised error string (or output text) that
	// drove the most recent Record call. Empty after a successful
	// Record.
	LastKind string
	// Streak is the number of consecutive same-kind errors observed
	// on this tool. Zero after a successful Record.
	Streak int
	// Open reports whether the breaker has tripped (Streak >=
	// threshold). The dispatch layer uses this as the escalate signal.
	Open bool
}

type toolState struct {
	lastKind string
	streak   int
}

type stats struct {
	totalErrors int
	totalTrips  int
}

// New constructs a Counter with the given threshold. threshold ≤0
// falls back to DefaultThreshold so a misconfigured caller can't
// disable the breaker by accident.
func New(threshold int) *Counter {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	return &Counter{
		threshold: threshold,
		tools:     map[string]*toolState{},
	}
}

// Record updates the breaker for tool given an error/output string.
// Pass the empty string (or the all-whitespace equivalent) on a
// successful tool call to clear the streak. Returns the post-update
// State so the caller can inspect Open without a follow-up call.
//
// A nil *Counter records nothing and returns a zero State — keeps
// callers free of "if c != nil" plumbing.
func (c *Counter) Record(tool, errOrOutput string) State {
	if c == nil || tool == "" {
		return State{Tool: tool}
	}
	kind := normalise(errOrOutput)

	c.mu.Lock()
	defer c.mu.Unlock()

	st, ok := c.tools[tool]
	if !ok {
		st = &toolState{}
		c.tools[tool] = st
	}

	if kind == "" {
		// Success path: clear the streak.
		st.lastKind = ""
		st.streak = 0
		return State{Tool: tool, Streak: 0, Open: false}
	}

	c.totals.totalErrors++
	if st.lastKind == kind {
		st.streak++
	} else {
		st.lastKind = kind
		st.streak = 1
	}
	open := st.streak >= c.threshold
	if open {
		c.totals.totalTrips++
	}
	return State{
		Tool:     tool,
		LastKind: st.lastKind,
		Streak:   st.streak,
		Open:     open,
	}
}

// Reset clears any breaker state for tool. Operator-facing
// `/reset-breaker <tool>` — useful when the operator changes the
// underlying device state and wants to retry without bouncing the
// session. Reset on an unknown tool is a no-op.
func (c *Counter) Reset(tool string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.tools, tool)
}

// ResetAll clears every breaker. Bound to a session-clear hook.
func (c *Counter) ResetAll() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools = map[string]*toolState{}
}

// State returns the current breaker state for tool without modifying
// it. Useful for tests + diagnostics.
func (c *Counter) State(tool string) State {
	if c == nil {
		return State{Tool: tool}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	st, ok := c.tools[tool]
	if !ok {
		return State{Tool: tool}
	}
	return State{
		Tool:     tool,
		LastKind: st.lastKind,
		Streak:   st.streak,
		Open:     st.streak >= c.threshold,
	}
}

// Snapshot returns aggregate stats since process start (or since the
// last NewCounter call). Caller-owned; safe to mutate.
type Snapshot struct {
	Threshold   int
	TotalErrors int
	TotalTrips  int
	OpenTools   []string // tools currently in the open state
}

// Snapshot returns a point-in-time view of the breaker's totals plus
// the list of tools currently in the open state. Used by /stats and
// the future report generator.
func (c *Counter) Snapshot() Snapshot {
	if c == nil {
		return Snapshot{Threshold: DefaultThreshold}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var open []string
	for name, st := range c.tools {
		if st.streak >= c.threshold {
			open = append(open, name)
		}
	}
	return Snapshot{
		Threshold:   c.threshold,
		TotalErrors: c.totals.totalErrors,
		TotalTrips:  c.totals.totalTrips,
		OpenTools:   open,
	}
}

// EscalationMessage is the canonical structured marker the dispatch
// layer prepends to a tool result when the breaker is open. Wrapped
// in <circuit-breaker-open>…</circuit-breaker-open> so the model can
// route on it the same way it routes on <untrusted-hardware-output>.
//
// The message includes the streak count and the canonical error
// kind so the model has enough context to pick a different
// approach. We deliberately avoid prescribing a remedy — the model
// picks based on tool semantics.
//
// LastKind is the normalised error string from prior failed
// dispatches. Tool error messages often echo attacker-controlled
// content (a wifi_join error message embeds the target SSID; an
// nfc_apdu error embeds the card UID), so a tool that consistently
// failed three times with `</circuit-breaker-open>` somewhere in
// the body would propagate that literal into this block — letting
// an attacker close the wrapper early and inject downstream
// instructions. Mirror the defense in
// agent.quarantineOutput (v0.134): rewrite literal close tags to
// `< /circuit-breaker-open>` (single space after `<`), which
// renders almost identically but is structurally NOT a close tag.
func EscalationMessage(state State) string {
	if !state.Open {
		return ""
	}
	var b strings.Builder
	b.WriteString("<circuit-breaker-open>\n")
	b.WriteString("Tool ")
	b.WriteString(state.Tool)
	b.WriteString(" has failed ")
	writeInt(&b, state.Streak)
	b.WriteString(" consecutive times with the same error. ")
	b.WriteString("Stop retrying this tool with these inputs; pick a different approach or surface a clarifying question to the operator.\n")
	if state.LastKind != "" {
		b.WriteString("Repeated error: ")
		b.WriteString(neutralizeCloseTag(state.LastKind))
		b.WriteString("\n")
	}
	b.WriteString("</circuit-breaker-open>")
	return b.String()
}

// neutralizeCloseTag rewrites any literal `</circuit-breaker-open>`
// inside content to `< /circuit-breaker-open>`. See
// EscalationMessage's docstring for why and
// agent.quarantineOutput.neutralizeCloseTag (v0.134) for the
// parallel pattern.
func neutralizeCloseTag(content string) string {
	return strings.ReplaceAll(content, "</circuit-breaker-open>", "< /circuit-breaker-open>")
}

// writeInt avoids strconv just for one int — the strings.Builder is
// already in scope and the breaker package keeps its dependency
// surface deliberately tiny.
func writeInt(b *strings.Builder, n int) {
	if n == 0 {
		b.WriteByte('0')
		return
	}
	if n < 0 {
		b.WriteByte('-')
		n = -n
	}
	var digits [20]byte
	i := len(digits)
	for n > 0 {
		i--
		digits[i] = '0' + byte(n%10)
		n /= 10
	}
	b.Write(digits[i:])
}

// normalise reduces an error or output string to its canonical
// "kind" form for streak matching. Trims, lower-cases, collapses
// whitespace runs to single spaces. The aim is to treat
// "loader_close: device busy" and "loader_close: device  busy "
// as the same kind — the LLM sometimes retries with a slightly
// different prompt, but the underlying error string is a tight
// signal we want to act on.
func normalise(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	// Collapse internal whitespace runs.
	var b strings.Builder
	b.Grow(len(s))
	prevSpace := false
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			if prevSpace {
				continue
			}
			prevSpace = true
			b.WriteByte(' ')
			continue
		}
		prevSpace = false
		b.WriteRune(r)
	}
	return b.String()
}
