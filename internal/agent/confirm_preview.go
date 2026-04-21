package agent

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
)

// MinimumConfirmDelay is the minimum wall time that must pass between
// rendering a high-risk confirmation preview and accepting a user
// approval keystroke. Two seconds matches the Warp Terminal precedent
// for risky-command UX: long enough to absorb an accidental reflex,
// short enough not to feel laggy. Low-risk prompts use the gate too so
// accidental Enter keypresses on a fast-moving transcript don't
// silently authorise a transmit.
const MinimumConfirmDelay = 2 * time.Second

// ConfirmDelayGate records when a confirmation prompt was first shown
// and reports whether the enforced delay has elapsed. The gate is
// time-source-agnostic (the clock can be stubbed for tests); callers
// invoke Show() once the prompt is visible, then check Open() (or
// Remaining()) before accepting a decision keystroke.
//
// Intended usage at a REPL:
//
//	g := NewConfirmDelayGate(MinimumConfirmDelay)
//	g.Show()
//	for {
//	    key := readKey()
//	    if key == "y" && !g.Open() {
//	        // swallow — user pressed too fast
//	        continue
//	    }
//	    ...
//	}
type ConfirmDelayGate struct {
	shownAt time.Time
	delay   time.Duration
	now     func() time.Time
}

// NewConfirmDelayGate builds a gate with the given minimum delay. The
// gate is closed until Show() is called.
func NewConfirmDelayGate(delay time.Duration) *ConfirmDelayGate {
	return &ConfirmDelayGate{delay: delay, now: time.Now}
}

// Show starts the clock on the delay window. Call once the prompt
// text has been rendered to the terminal. Safe to call multiple times
// — each call resets the countdown, useful if the prompt is redrawn
// on a resize.
func (g *ConfirmDelayGate) Show() {
	g.shownAt = g.now()
}

// Remaining returns how much of the delay window is left. A zero or
// negative return means the gate is open.
func (g *ConfirmDelayGate) Remaining() time.Duration {
	if g.shownAt.IsZero() {
		return g.delay
	}
	return g.delay - g.now().Sub(g.shownAt)
}

// Open reports whether enough time has elapsed since Show() for an
// approval keystroke to be accepted.
func (g *ConfirmDelayGate) Open() bool {
	return g.Remaining() <= 0
}

// FormatConfirmPreview renders a multi-line boxed preview for the
// given ConfirmRequest. The preview pulls well-known fields (frequency,
// file path, duration_seconds, protocol, data hex, target_os) out of
// the tool input JSON and surfaces them in a human-reviewable shape
// before the operator approves. Low-risk tools return the empty string
// so the caller can fall back to the existing compact prompt.
//
// Output shape (ASCII box, no colors — colors are the caller's
// responsibility so tests can assert exact content):
//
//	┌─ About to run wifi_deauth ──────────────┐
//	│ risk: critical                          │
//	│ duration_seconds: 30                    │
//	└─────────────────────────────────────────┘
//
// The caller is expected to paint this to the screen, invoke
// ConfirmDelayGate.Show(), then render its own colored prompt line.
func FormatConfirmPreview(req ConfirmRequest) string {
	if req.Risk < risk.High {
		return ""
	}

	lines := []string{
		"risk: " + req.Risk.String(),
	}

	// Best-effort parse: if the input isn't JSON or carries no known
	// fields, we still render the risk + tool name.
	var params map[string]any
	if err := json.Unmarshal(req.Input, &params); err == nil {
		for _, key := range previewFieldOrder {
			if v, ok := params[key]; ok {
				val := formatPreviewValue(key, v)
				if val != "" {
					lines = append(lines, fmt.Sprintf("%s: %s", key, val))
				}
			}
		}
	}

	title := "About to run " + req.Tool

	return renderConfirmBox(title, lines)
}

// previewFieldOrder lists the well-known input fields to surface in
// the boxed preview, in the order the operator is most likely to care
// about. Unknown fields are not surfaced — the goal is a clean
// summary, not a full dump.
var previewFieldOrder = []string{
	"file",
	"frequency",
	"protocol",
	"address",
	"command",
	"data",
	"key_hex",
	"hex",
	"duration_seconds",
	"timeout_seconds",
	"target_os",
	"path",
	"filename",
}

// formatPreviewValue coerces common JSON types to compact display
// strings. Big-int frequencies render in MHz-friendly form when they
// look like Sub-GHz frequencies.
func formatPreviewValue(key string, v any) string {
	switch t := v.(type) {
	case string:
		if len(t) > 72 {
			return t[:69] + "…"
		}
		return t
	case float64:
		if key == "frequency" && t > 100_000 {
			return fmt.Sprintf("%d Hz (%.3f MHz)", int64(t), t/1_000_000)
		}
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case bool:
		return fmt.Sprintf("%t", t)
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return ""
		}
		out := string(b)
		if len(out) > 72 {
			out = out[:69] + "…"
		}
		return out
	}
}

// renderConfirmBox draws a unicode box around the title + body lines.
// Width auto-fits the widest line up to a hard cap so a pathological
// payload can't overflow into a deformed box on narrow terminals.
func renderConfirmBox(title string, lines []string) string {
	const maxWidth = 72
	width := len(title) + 4 // title framing "─ %s ─"
	for _, l := range lines {
		if w := len(l) + 2; w > width { // "│ %s "
			width = w
		}
	}
	if width > maxWidth {
		width = maxWidth
	}
	if width < len(title)+6 {
		width = len(title) + 6
	}

	var b strings.Builder
	// Top: "┌─ title ─────┐"
	fmt.Fprintf(&b, "┌─ %s ", title)
	for i := len(title) + 4; i < width-1; i++ {
		b.WriteString("─")
	}
	b.WriteString("┐\n")

	for _, l := range lines {
		clip := l
		if len(clip) > width-2 {
			clip = clip[:width-2]
		}
		fmt.Fprintf(&b, "│ %-*s│\n", width-2, clip)
	}

	b.WriteString("└")
	for i := 0; i < width-1; i++ {
		b.WriteString("─")
	}
	b.WriteString("┘\n")
	return b.String()
}
