package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"golang.org/x/term"
)

// --- Tool-arg rendering --------------------------------------------------

// truncateArgs renders a tool's JSON input for inline display: collapsed
// whitespace, trimmed to 60 chars. Empty args render as "{}".
func truncateArgs(raw []byte) string {
	s := strings.Join(strings.Fields(string(raw)), " ")
	if s == "" {
		return "{}"
	}
	const max = 60
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}

// truncateArgsTo renders a tool's JSON input collapsed to one line and
// capped at max chars. Empty args render as "{}".
func truncateArgsTo(raw []byte, max int) string {
	s := strings.Join(strings.Fields(string(raw)), " ")
	if s == "" {
		return "{}"
	}
	if max < 4 {
		max = 4
	}
	if len(s) > max {
		s = s[:max-1] + "…"
	}
	return s
}

// --- Risk confirmation ---------------------------------------------------

// confirmState carries an in-flight risk-confirmation request. The callback
// goroutine populates it; the REPL event loop drains it on the next key.
// typing buffers characters while the user spells out "all" + Enter — we
// refuse to bind approve-all to a single key since one stray paste would
// disable the risk gate for the rest of the turn.
type confirmState struct {
	req    agent.ConfirmRequest
	result chan agent.Decision
	typing []rune
}

// decisionLabel maps agent.Decision onto the label the Prom counter expects.
func decisionLabel(d agent.Decision) string {
	switch d {
	case agent.DecisionApprove:
		return "approve"
	case agent.DecisionApproveAll:
		return "approve_all"
	case agent.DecisionDeny:
		return "deny"
	default:
		return "unknown"
	}
}

// renderConfirmPrompt paints the two-line prompt shown before a destructive
// tool runs. Lives inside ed.writeOutput so it plays nicely with streaming
// output and tool-status redraws.
func renderConfirmPrompt(req agent.ConfirmRequest, cols int) {
	pad := strings.Repeat(" ", boxPad)
	// Size the args budget to the terminal width so a long JSON blob can't
	// overflow into a right-border-munging mess.
	argsBudget := cols - boxPad - 2 - len("⚠ About to run ") - len(req.Tool) - 1
	if argsBudget < 20 {
		argsBudget = 20
	}
	args := truncateArgsTo(req.Input, argsBudget)
	fmt.Fprintf(os.Stderr, "\r\033[K\n%s%s⚠ About to run%s %s%s%s %s%s%s\n",
		pad, yellow, reset, bold, req.Tool, reset, dim, args, reset)
	riskStr := fmt.Sprintf("%s  risk: %s%s%s", pad, riskColor(req.Risk.String()), req.Risk.String(), reset)
	approve := fmt.Sprintf("%s[y]%s approve", bold+green, reset)
	approveAll := fmt.Sprintf("type %sall%s+Enter to approve all remaining", bold+cyan, reset)
	deny := fmt.Sprintf("%s[N]%s deny (default)", bold+red, reset)
	if cols < 80 {
		fmt.Fprintf(os.Stderr, "%s\n", riskStr)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, approve)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, deny)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, approveAll)
		return
	}
	fmt.Fprintf(os.Stderr, "%s · %s  %s  %s\n", riskStr, approve, deny, approveAll)
}

// resolveConfirmKey interprets one keystroke as a confirmation answer.
// Returns true when the key resolved the prompt (and the caller should
// clear pendingConfirm). Non-decision keys (cursor moves, etc.) are
// dropped so stray arrow-key escapes don't accidentally approve.
//
// Single-key answers: y/Y approves this one, n/N denies, Enter/Esc/Ctrl+C
// denies. Any other printable key flips into "type-in" mode: we buffer
// characters until Enter. If the buffer equals "all", that's approve-all;
// anything else denies. This is deliberately slower than a single key so
// a stray paste or leaning on the keyboard can't disable the risk gate.
func resolveConfirmKey(cs *confirmState, k keyEvent, ed *lineEditor) bool {
	// Typed-word mode: the user has started spelling something, so queue
	// printable runes and act only on Enter / backspace / cancel keys.
	if cs.typing != nil {
		switch k.kind {
		case keyEnter:
			typed := strings.ToLower(strings.TrimSpace(string(cs.typing)))
			var d agent.Decision
			if typed == "all" {
				d = agent.DecisionApproveAll
			} else {
				d = agent.DecisionDeny
			}
			return confirmResolve(cs, d, ed)
		case keyBackspace:
			if len(cs.typing) > 0 {
				cs.typing = cs.typing[:len(cs.typing)-1]
			}
			return false
		case keyCtrlC, keyCtrlD, keyEOF:
			return confirmResolve(cs, agent.DecisionDeny, ed)
		case keyRune:
			cs.typing = append(cs.typing, k.r)
			return false
		default:
			return false
		}
	}

	switch k.kind {
	case keyRune:
		switch k.r {
		case 'y', 'Y':
			return confirmResolve(cs, agent.DecisionApprove, ed)
		case 'n', 'N':
			return confirmResolve(cs, agent.DecisionDeny, ed)
		default:
			// Start type-in mode. Buffer the rune and show a hint so the
			// user knows approve-all needs the full word.
			cs.typing = []rune{k.r}
			ed.writeOutput(func() {
				pad := strings.Repeat(" ", boxPad)
				fmt.Fprintf(os.Stderr, "%s  %s(type `all` then Enter to approve all remaining this turn, Enter to cancel)%s\n",
					pad, dim, reset)
			})
			return false
		}
	case keyEnter, keyCtrlC, keyCtrlD, keyEOF:
		return confirmResolve(cs, agent.DecisionDeny, ed)
	}
	return false
}

func confirmResolve(cs *confirmState, d agent.Decision, ed *lineEditor) bool {
	ed.writeOutput(func() {
		var label string
		switch d {
		case agent.DecisionApprove:
			label = green + "● approved" + reset
		case agent.DecisionApproveAll:
			label = cyan + "● approved (all remaining)" + reset
		case agent.DecisionDeny:
			label = red + "● denied" + reset
		}
		pad := strings.Repeat(" ", boxPad)
		fmt.Fprintf(os.Stderr, "%s  %s\n", pad, label)
	})
	select {
	case cs.result <- d:
	default:
	}
	return true
}

// --- Turn status bar -----------------------------------------------------

// spinnerFrames cycles through braille dots at 100ms intervals; looks like
// a smooth pulse in any modern terminal that renders unicode.
var spinnerFrames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// formatElapsed renders a running turn's elapsed time compactly: seconds
// under a minute, "Nm SSs" at or above a minute.
func formatElapsed(d time.Duration) string {
	s := int(d.Round(time.Second) / time.Second)
	if s < 60 {
		return fmt.Sprintf("%ds", s)
	}
	return fmt.Sprintf("%dm%02ds", s/60, s%60)
}

// runTurnStatusBar ticks every 100ms and redraws the box's top border with
// a spinner, the current note ("Thinking" / "Running <tool>" / "Responding"),
// elapsed time, tool count, and a Ctrl+C hint. When a prompt is queued it
// also appends "1 queued". Exits as soon as ed.running goes false, leaving
// a plain border behind.
func runTurnStatusBar(ed *lineEditor, started *atomic.Pointer[time.Time], note *atomic.Pointer[string], tools *atomic.Int32) {
	if !ed.ui.enabled {
		return
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		if !ed.running.Load() {
			ed.outputMu.Lock()
			ed.ui.drawStatusBorder("")
			ed.renderLocked()
			ed.outputMu.Unlock()
			return
		}
		<-ticker.C
		if !ed.running.Load() {
			ed.outputMu.Lock()
			ed.ui.drawStatusBorder("")
			ed.renderLocked()
			ed.outputMu.Unlock()
			return
		}
		startedAt := started.Load()
		if startedAt == nil {
			continue
		}
		n := ""
		if p := note.Load(); p != nil {
			n = *p
		}
		var parts []string
		parts = append(parts, fmt.Sprintf("%c %s", spinnerFrames[frame], n))
		parts = append(parts, formatElapsed(time.Since(*startedAt)))
		if tc := tools.Load(); tc > 0 {
			parts = append(parts, fmt.Sprintf("%d tools", tc))
		}
		if ed.hasQueued.Load() {
			parts = append(parts, "1 queued")
		}
		parts = append(parts, "Ctrl+C to interrupt")
		status := strings.Join(parts, " · ")
		ed.outputMu.Lock()
		ed.ui.drawStatusBorder(status)
		ed.renderLocked()
		ed.outputMu.Unlock()
		frame = (frame + 1) % len(spinnerFrames)
	}
}

// --- Tool output preview -------------------------------------------------

// outputPreview returns a single dim line summarising a tool's stdout, or a
// red one-liner when the tool errored. Returns "" for empty output, or when
// the output is only a Flipper CLI prompt character — in those cases we
// leave the scroll area alone. Short successful outputs (<20 chars on the
// first line) are also skipped — they don't teach the user anything the
// tool name + duration didn't already show. Errors always render regardless
// of length so failures stay visible.
func outputPreview(out string, isErr bool) string {
	var line string
	for _, raw := range strings.Split(out, "\n") {
		raw = strings.TrimRight(raw, "\r")
		raw = strings.TrimSpace(raw)
		if raw != "" {
			line = raw
			break
		}
	}
	if line == "" || line == ">" {
		return ""
	}
	if !isErr && len(line) < 20 {
		return ""
	}
	line = collapseWS(line)
	cols := 80
	if c, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && c > 20 {
		cols = c
	}
	maxW := cols - 8
	if maxW < 20 {
		maxW = 20
	}
	if len(line) > maxW {
		line = line[:maxW-1] + "…"
	}
	if isErr {
		return "    " + red + line + reset
	}
	return "    " + dim + line + reset
}
