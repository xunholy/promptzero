package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/risk"
	streampkg "github.com/xunholy/promptzero/internal/streaming"
	"github.com/xunholy/promptzero/internal/voice"
	"github.com/xunholy/promptzero/internal/watch"
	"github.com/xunholy/promptzero/internal/webhook"
	"golang.org/x/term"
)

// turnResult is the outcome of one ai.Run, delivered back to the REPL
// select loop so it can update UI state on the main goroutine.
type turnResult struct {
	response string
	err      error
}

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

// confirmState carries an in-flight risk-confirmation request. The
// callback goroutine populates it; the REPL event loop drains it on
// the next key. typing buffers characters while the user spells out
// "all" (approve-all) or types a revision prompt — we refuse to bind
// either to a single key since one stray paste would otherwise
// disable the risk gate or inject revisions for the rest of the
// turn. typingKind discriminates between "all" and revise modes.
type confirmState struct {
	req        agent.ConfirmRequest
	result     chan agent.ConfirmResponse
	typing     []rune
	typingKind confirmTypingKind
	// gate enforces the minimum 2-second delay between rendering the
	// confirmation prompt and accepting a positive consent keystroke.
	// Negative consent (n, Esc, Ctrl+C) always passes immediately.
	gate *agent.ConfirmDelayGate
}

// confirmTypingKind records what the buffered characters represent
// so the Enter handler knows how to interpret them.
type confirmTypingKind int

const (
	typingNone confirmTypingKind = iota
	typingFreeText
	typingRevise
)

// decisionLabel maps agent.Decision onto the label the Prom counter expects.
func decisionLabel(d agent.Decision) string {
	switch d {
	case agent.DecisionApprove:
		return "approve"
	case agent.DecisionApproveAll:
		return "approve_all"
	case agent.DecisionDeny:
		return "deny"
	case agent.DecisionRevise:
		return "revise"
	default:
		return "unknown"
	}
}

// renderConfirmPrompt paints the two-line prompt shown before a destructive
// tool runs. Lives inside ed.writeOutput so it plays nicely with streaming
// output and tool-status redraws.
//
// For risk.High and risk.Critical tools, a multi-line boxed preview
// (FormatConfirmPreview) is rendered *above* the compact prompt so the
// operator can review the frequency / file path / payload hex before
// approving. Low-risk tools fall through to the compact prompt only.
//
// Critical tools get a stricter prompt: no single-key approve, no
// blanket approve-all. The operator must type the word `confirm` so a
// stray keystroke or approve-all reflex from an earlier tool can't
// silently authorise something destructive.
func renderConfirmPrompt(req agent.ConfirmRequest, cols int) {
	if preview := agent.FormatConfirmPreview(req); preview != "" {
		fmt.Fprintf(os.Stderr, "\r\033[K\n%s%s%s", yellow, preview, reset)
	}
	if req.Diff != "" {
		renderConfirmDiff(req.Diff)
	}
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
	deny := fmt.Sprintf("%s[N]%s deny (default)", bold+red, reset)

	if req.Risk == risk.Critical {
		approve := fmt.Sprintf("type %sconfirm%s+Enter to approve", bold+green, reset)
		if cols < 80 {
			fmt.Fprintf(os.Stderr, "%s\n", riskStr)
			fmt.Fprintf(os.Stderr, "%s    %s\n", pad, approve)
			fmt.Fprintf(os.Stderr, "%s    %s\n", pad, deny)
			return
		}
		fmt.Fprintf(os.Stderr, "%s · %s  %s\n", riskStr, approve, deny)
		return
	}

	approve := fmt.Sprintf("%s[y]%s approve", bold+green, reset)
	approveAll := fmt.Sprintf("type %sall%s+Enter to approve all remaining", bold+cyan, reset)
	if cols < 80 {
		fmt.Fprintf(os.Stderr, "%s\n", riskStr)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, approve)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, deny)
		fmt.Fprintf(os.Stderr, "%s    %s\n", pad, approveAll)
		return
	}
	fmt.Fprintf(os.Stderr, "%s · %s  %s  %s\n", riskStr, approve, deny, approveAll)
}

// renderConfirmDiff paints the unified-diff preview attached to a
// medium-risk file-write confirmation. Lines are coloured per git
// convention: green for additions, red for deletions, dim for the
// file/hunk headers, default for context lines.
func renderConfirmDiff(d string) {
	pad := strings.Repeat(" ", boxPad)
	fmt.Fprintf(os.Stderr, "\r\033[K\n")
	for _, line := range strings.Split(d, "\n") {
		if line == "" {
			continue
		}
		var colored string
		switch {
		case strings.HasPrefix(line, "+++ "), strings.HasPrefix(line, "--- "):
			colored = dim + line + reset
		case strings.HasPrefix(line, "@@"):
			colored = bold + line + reset
		case strings.HasPrefix(line, "+"):
			colored = green + line + reset
		case strings.HasPrefix(line, "-"):
			colored = red + line + reset
		default:
			colored = line
		}
		fmt.Fprintf(os.Stderr, "%s%s\n", pad, colored)
	}
}

// resolveConfirmKey interprets one keystroke as a confirmation answer.
// Returns true when the key resolved the prompt (and the caller should
// clear pendingConfirm). Non-decision keys (cursor moves, etc.) are
// dropped so stray arrow-key escapes don't accidentally approve.
//
// Non-critical risk:
//   - y / Y approves this one
//   - n / N / Enter / Esc / Ctrl+C denies
//   - Any other printable key enters type-in mode; typing `all` + Enter
//     approve-alls remaining tools in the turn, anything else denies.
//
// Critical risk (destructive actions, reflash, key writes, RF TX-in-anger,
// BadUSB run, etc.): no single-key approve, no approve-all. The operator
// must type the word `confirm` + Enter. Rationale: a stray `y` from the
// previous prompt or a reflexive type-`all` shouldn't be able to cross
// the highest-risk gate.
func resolveConfirmKey(cs *confirmState, k keyEvent, ed *lineEditor) bool {
	critical := cs.req.Risk == risk.Critical

	// Typed-word mode: the user has started spelling something, so queue
	// printable runes and act only on Enter / backspace / cancel keys.
	if cs.typing != nil {
		switch k.kind {
		case keyEnter:
			typed := strings.TrimSpace(string(cs.typing))
			if cs.typingKind == typingRevise {
				// Any revision text (even empty) finalises the
				// revise decision; the agent treats empty as a
				// placeholder and keeps the loop structured.
				return confirmResolveRevision(cs, typed, ed)
			}
			lower := strings.ToLower(typed)
			var d agent.Decision
			switch {
			case critical && lower == "confirm":
				if cs.gate != nil && !cs.gate.Open() {
					ed.writeOutput(func() {
						pad := strings.Repeat(" ", boxPad)
						fmt.Fprintf(os.Stderr, "%s  %s(wait — approval opens in %.0fs)%s\n",
							pad, dim, cs.gate.Remaining().Seconds(), reset)
					})
					cs.typing = nil // reset so they can try again
					return false
				}
				d = agent.DecisionApprove
			case !critical && lower == "all":
				if cs.gate != nil && !cs.gate.Open() {
					ed.writeOutput(func() {
						pad := strings.Repeat(" ", boxPad)
						fmt.Fprintf(os.Stderr, "%s  %s(wait — approval opens in %.0fs)%s\n",
							pad, dim, cs.gate.Remaining().Seconds(), reset)
					})
					cs.typing = nil // reset so they can try again
					return false
				}
				d = agent.DecisionApproveAll
			default:
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
		if critical {
			// No single-key approve path: every rune (even `y`) enters
			// type-in mode and only the exact word `confirm` authorises.
			cs.typing = []rune{k.r}
			cs.typingKind = typingFreeText
			ed.writeOutput(func() {
				pad := strings.Repeat(" ", boxPad)
				fmt.Fprintf(os.Stderr, "%s  %s(type `confirm` then Enter to approve this critical action, Enter to cancel)%s\n",
					pad, dim, reset)
			})
			return false
		}
		switch k.r {
		case 'y', 'Y':
			if cs.gate != nil && !cs.gate.Open() {
				ed.writeOutput(func() {
					pad := strings.Repeat(" ", boxPad)
					fmt.Fprintf(os.Stderr, "%s  %s(wait — approval opens in %.0fs)%s\n",
						pad, dim, cs.gate.Remaining().Seconds(), reset)
				})
				return false
			}
			return confirmResolve(cs, agent.DecisionApprove, ed)
		case 'n', 'N':
			return confirmResolve(cs, agent.DecisionDeny, ed)
		case 'r', 'R':
			// Revise: enter type-in mode for the revision prompt,
			// which is forwarded to the model verbatim on Enter.
			cs.typing = []rune{} // empty buffer — the trigger rune itself is consumed
			cs.typingKind = typingRevise
			ed.writeOutput(func() {
				pad := strings.Repeat(" ", boxPad)
				fmt.Fprintf(os.Stderr, "%s  %s(type the revision the agent should apply, then Enter; Ctrl+C to cancel)%s\n",
					pad, dim, reset)
			})
			return false
		default:
			// Start type-in mode. Buffer the rune and show a hint so the
			// user knows approve-all needs the full word.
			cs.typing = []rune{k.r}
			cs.typingKind = typingFreeText
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
		case agent.DecisionRevise:
			label = yellow + "● revision requested" + reset
		}
		pad := strings.Repeat(" ", boxPad)
		fmt.Fprintf(os.Stderr, "%s  %s\n", pad, label)
	})
	select {
	case cs.result <- agent.ConfirmResponse{Decision: d}:
	default:
	}
	return true
}

// confirmResolveRevision finalises the DecisionRevise path — the
// buffered rune slice becomes the revision text forwarded to the
// model. Empty revisions are allowed; the agent handles them by
// treating the revision as an operator-initiated skip with no
// specific guidance.
func confirmResolveRevision(cs *confirmState, text string, ed *lineEditor) bool {
	ed.writeOutput(func() {
		pad := strings.Repeat(" ", boxPad)
		display := text
		if display == "" {
			display = "(no revision text)"
		}
		fmt.Fprintf(os.Stderr, "%s  %s● revision: %s%s\n", pad, yellow, display, reset)
	})
	select {
	case cs.result <- agent.ConfirmResponse{Decision: agent.DecisionRevise, Revision: text}:
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

// renderStreamFrame formats one streaming-tool partial frame as a
// single dim, indented line for the REPL scroll area. Mirrors the
// look of outputPreview / the tool start/finish lines so the frames
// blend in. Long bytes are truncated to the terminal width minus a
// small margin; non-printable bytes get the standard %q escape so a
// noisy capture (control chars, ANSI) does not corrupt the screen.
func renderStreamFrame(f streampkg.Frame) string {
	line := strings.TrimRight(string(f.Bytes), "\r\n")
	line = collapseWS(line)
	if line == "" {
		return ""
	}
	// Quote anything with control characters or escape sequences so
	// the operator-facing log can't be hijacked by a hostile capture.
	if needsQuote(line) {
		quoted := fmt.Sprintf("%q", line)
		// strip surrounding quotes for a slightly tighter render
		line = strings.TrimSuffix(strings.TrimPrefix(quoted, `"`), `"`)
	}
	cols := 80
	if c, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && c > 20 {
		cols = c
	}
	maxW := cols - 12
	if maxW < 20 {
		maxW = 20
	}
	if len(line) > maxW {
		line = line[:maxW-1] + "…"
	}
	return fmt.Sprintf("    %s· %s%s%s", dim, line, reset, "")
}

// needsQuote reports whether s contains any byte outside printable
// ASCII. Newlines were already stripped by the caller; this is the
// "non-printable / control-char" check.
func needsQuote(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

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

// --- REPL entry point ----------------------------------------------------

// enterREPL takes over the terminal for interactive use: sets up the
// persistent input box, puts stdin into raw mode, wires the agent
// callbacks (text deltas, tool status, risk confirmation, hot-plug
// reconnects), starts the optional filesystem watcher, and runs the
// keystroke / turn-completion select loop until the user exits.
//
// Expects deps to be populated with every subsystem input; the REPL-
// owned fields (ed, watchMgr, busy) are set internally. Returns nil on
// clean exit and any terminal-setup error otherwise.
func enterREPL(deps *REPLDeps) error {
	ctx := deps.ctx
	sh := deps.sh
	ai := deps.ai
	flip := deps.flip
	rec := deps.rec
	wh := deps.wh
	voiceEngine := deps.voiceEngine

	if deps.voiceMode {
		if voiceEngine == nil {
			return fmt.Errorf("voice mode requires OPENAI_API_KEY")
		}
		if !voice.Available() {
			return fmt.Errorf("voice mode requires 'sox' (apt install sox / brew install sox)")
		}
		fmt.Fprintf(os.Stderr, "  %sVoice mode ON%s — press Enter to record, speak, stops on silence.\n\n", bold, reset)
	}

	fmt.Fprintf(os.Stderr, "  Type %s/help%s for commands, or just describe what you want.\n", dim, reset)
	fmt.Fprintf(os.Stderr, "  %sFlipper feedback:%s %s●%s blue LED while agent is working · %s●%s vibration on detection\n\n", dim, reset, blue, reset, green, reset)

	// --- Persistent input box at bottom of terminal ---
	ui := newTermUI()
	sh.setUI(ui)
	ui.setup()
	defer ui.teardown()

	// --- Raw-mode stdin so the user can keep typing while a turn runs ---
	stdinFd := int(os.Stdin.Fd())
	if term.IsTerminal(stdinFd) {
		oldState, err := term.MakeRaw(stdinFd)
		if err != nil {
			return fmt.Errorf("could not put the terminal into raw mode (the REPL needs raw stdin to render the persistent input box): %w — try running in a real TTY (no pipe / no `< file` redirection)", err)
		}
		// MakeRaw disables OPOST, which also turns off ONLCR - so a plain \n
		// in our output moves the cursor down without carriage-returning to
		// column 0. That's what was causing confirm-prompt row 2 and streamed
		// text to drift rightward across lines. Re-enable OPOST + ONLCR so
		// \n writes behave as line breaks again. Leaves ICANON/ECHO/ISIG off
		// (we still own input handling and Ctrl+C routing). Platform-specific
		// termios details live in main_termios_<goos>.go.
		enableOPOSTONLCR(stdinFd)
		restore := func() { _ = term.Restore(stdinFd, oldState) }
		sh.setStdinRestore(&restore)
		defer func() {
			sh.setStdinRestore(nil)
			restore()
		}()
	}

	ed := newLineEditor(ui)
	deps.ed = ed

	// Enable bracketed paste (DECSET 2004) so multi-line pastes arrive as a
	// single buffered event rather than one Enter per line, and disable on
	// teardown so the next shell doesn't inherit the mode.
	if ui.enabled {
		fmt.Fprint(os.Stderr, "\033[?2004h")
		defer fmt.Fprint(os.Stderr, "\033[?2004l")
	}

	// SIGWINCH: refresh dimensions, re-scroll, redraw box + input.
	// Windows has no SIGWINCH — watchWindowSize is a no-op there (see
	// main_os_windows.go). On Unix it registers the signal handler.
	stopWinch := watchWindowSize(func() {
		if !ui.resize() {
			return
		}
		ed.outputMu.Lock()
		fmt.Fprintf(os.Stderr, "\033[1;%dr", ui.Rows()-boxHeight)
		ui.drawBoxFrame()
		ed.renderLocked()
		ed.outputMu.Unlock()
	})
	defer stopWinch()

	// Surface hot-plug reconnect phases in the output area. Keeps the user
	// informed when the Flipper drops off USB (WSL vhci_hcd glitch, physical
	// replug, etc.) without requiring /quit + relaunch.
	flip.SetReconnectCallback(func(phase, message string) {
		ed.writeOutput(func() {
			switch phase {
			case "start":
				fmt.Fprintf(os.Stderr, "  %s●%s %s\n", yellow, reset, message)
			case "success":
				fmt.Fprintf(os.Stderr, "  %s●%s %s\n", green, reset, message)
			case "fail":
				fmt.Fprintf(os.Stderr, "  %s●%s %s\n", red, reset, message)
			}
		})
	})

	// streaming is true while text deltas are actively landing on the
	// current output line. State transitions (tool start/finish, turn end)
	// flip it back to false so the next delta re-clears the status line.
	var streaming atomic.Bool

	// streamAbortRequested is set by Ctrl+G during a streaming tool
	// run. The agent's stream callback (installed below) inspects it
	// per frame and returns false when set, which fires
	// sink.Abort() + ctx cancel via the existing dispatch path. Reset
	// at the start of every dispatchTurn so a stale request from a
	// prior turn cannot poison the next one.
	var streamAbortRequested atomic.Bool

	// --- Turn status bar (Claude-Code-style spinner on top border) ---
	// turnStartedAt + turnNote drive the spinner goroutine below. The
	// spinner redraws the box's top border every ~100ms with the current
	// note (Thinking / Running <tool> / Responding) and elapsed time. It
	// exits cleanly once ed.running goes false.
	var turnStartedAt atomic.Pointer[time.Time]
	var turnNote atomic.Pointer[string]
	var turnToolCount atomic.Int32
	setNote := func(s string) { turnNote.Store(&s) }

	// Stream assistant text as it arrives. writeDelta preserves the
	// cursor position between chunks using DEC save/restore, so
	// successive tokens flow naturally across the scroll region instead of
	// clobbering each other at column 1 (which writeOutput would do).
	ai.SetTextDeltaCallback(func(td agent.TextDelta) {
		if streaming.CompareAndSwap(false, true) {
			setNote("Responding")
		}
		ed.writeDelta(td.Text)
	})

	// Tool-call status: routed through the editor so concurrent keystroke
	// redraws and tool events don't trample each other. Adds an inline
	// one-line output preview after each tool finish.
	ai.SetToolStatusCallback(func(ev agent.ToolEvent) {
		// End any in-flight delta stream cleanly before writing a status
		// line — the line editor's endDelta emits the closing newline.
		if streaming.Swap(false) {
			ed.endDelta()
		}
		ed.writeOutput(func() {
			switch ev.Phase {
			case "start":
				setNote("Running " + ev.Name)
				fmt.Fprintf(os.Stderr, "  %s▸%s %s %s%s%s\n", cyan, reset, ev.Name, dim, truncateArgs(ev.Input), reset)
			case "finish":
				setNote("Thinking")
				turnToolCount.Add(1)
				icon := green + "◦" + reset
				if ev.Err {
					icon = red + "✗" + reset
				}
				fmt.Fprintf(os.Stderr, "  %s %s %s(%s)%s\n", icon, ev.Name, dim, ev.Duration.Round(time.Millisecond), reset)
				if preview := outputPreview(ev.Output, ev.Err); preview != "" {
					fmt.Fprintln(os.Stderr, preview)
				}
			}
		})
		if ev.Phase == "finish" {
			status := "ok"
			if ev.Err {
				status = "error"
			}
			rec.RecordToolCall(ev.Name, risk.Classify(ev.Name).String(), status, ev.Duration)
			if strings.HasPrefix(ev.Name, "workflow_") {
				rec.RecordWorkflowRun(ev.Name, status, ev.Duration)
			}
			out := ev.Output
			if len(out) > 2048 {
				out = out[:2048] + "... [truncated]"
			}
			payload := map[string]any{
				"tool":        ev.Name,
				"input":       string(ev.Input),
				"duration_ms": ev.Duration.Milliseconds(),
				"error":       ev.Err,
				"output":      out,
			}
			wh.Fire(webhook.EventToolFinished, payload)
			if strings.HasPrefix(ev.Name, "workflow_") {
				wh.Fire(webhook.EventWorkflowCompleted, payload)
			}
		}
	})

	// --- Streaming tool frames ---
	// Tools that opt into streaming dispatch (e.g. subghz_receive)
	// emit one frame per partial result. Render each as a dim,
	// indented line under the running tool — matches the look of
	// the start/finish status lines from SetToolStatusCallback. The
	// callback returns false when streamAbortRequested is set
	// (Ctrl+G hotkey) so the agent's dispatcher fires
	// sink.Abort() + per-call ctx cancel; the streaming tool's
	// StreamHandler honours both signals and returns its partial
	// result via the normal final-string path.
	ai.SetToolStreamCallback(func(f streampkg.Frame) bool {
		// End any in-flight delta stream cleanly so the frame line
		// doesn't append to a half-flushed assistant token.
		if streaming.Swap(false) {
			ed.endDelta()
		}
		ed.writeOutput(func() {
			fmt.Fprintln(os.Stderr, renderStreamFrame(f))
		})
		// Consume the abort request — flip back to false so a
		// follow-up streaming tool in the same turn isn't aborted
		// by a stale flag. The agent's drain loop swallows post-
		// abort frames so this only fires once per abort.
		if streamAbortRequested.Swap(false) {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "    %s· (stop requested — finishing capture)%s\n", dim, reset)
			})
			return false
		}
		return true
	})

	// --- Risk confirmation prompt ---
	// The callback fires from the ai.Run goroutine. It parks a pendingConfirm
	// state and blocks on resultCh; the main REPL select loop routes the next
	// keystroke into that channel (see "pendingConfirm" check in the select
	// below) instead of the line editor.
	var pendingConfirm atomic.Pointer[confirmState]
	if deps.gateEnabled {
		ai.SetConfirmCallback(func(ctx context.Context, req agent.ConfirmRequest) agent.ConfirmResponse {
			promptPayload := map[string]any{
				"tool":  req.Tool,
				"risk":  req.Risk.String(),
				"input": string(req.Input),
			}
			wh.Fire(webhook.EventRiskPrompted, promptPayload)
			gate := agent.NewConfirmDelayGate(agent.MinimumConfirmDelay)
			resultCh := make(chan agent.ConfirmResponse, 1)
			pendingConfirm.Store(&confirmState{req: req, result: resultCh, gate: gate})
			ed.writeOutput(func() {
				renderConfirmPrompt(req, ui.Cols())
				gate.Show() // start the 2s clock after prompt is on screen
			})
			defer pendingConfirm.Store(nil)
			var resp agent.ConfirmResponse
			select {
			case resp = <-resultCh:
			case <-ctx.Done():
				resp = agent.ConfirmResponse{Decision: agent.DecisionDeny}
			}
			rec.RecordRiskPrompt(req.Tool, decisionLabel(resp.Decision))
			if resp.Decision == agent.DecisionDeny {
				denyPayload := map[string]any{
					"tool":  req.Tool,
					"risk":  req.Risk.String(),
					"input": string(req.Input),
				}
				wh.Fire(webhook.EventRiskDenied, denyPayload)
			}
			return resp
		})
	}

	keys := make(chan keyEvent, 64)
	go readKeys(keys)

	turnDone := make(chan turnResult, 4)

	var kbdCtrlCAt atomic.Int64

	dispatchTurn := func(input string) {
		streaming.Store(false)
		// Clear any stale Ctrl+G abort request from a prior turn so
		// the new turn's first streaming tool isn't immediately
		// aborted by a latched flag.
		streamAbortRequested.Store(false)
		ed.writeOutput(func() {
			pad := strings.Repeat(" ", boxPad)
			fmt.Fprintf(os.Stderr, "\n%s%s>%s %s%s%s\n", pad, dim, reset, dim, input, reset)
		})
		_ = flip.SetLED("b", 0xff)
		now := time.Now()
		turnStartedAt.Store(&now)
		turnToolCount.Store(0)
		setNote("Thinking")
		ed.running.Store(true)
		go runTurnStatusBar(ed, &turnStartedAt, &turnNote, &turnToolCount)
		turnCtx, releaseTurn := sh.withCancel(ctx)
		go func() {
			// Custom recover (not obs.SafeGo) so a panic in ai.Run
			// still releases the turn ctx + sends to turnDone — the
			// REPL receiver blocks on that channel and would hang
			// otherwise. Surface the panic as an error to the user
			// rather than crashing the whole CLI.
			var res turnResult
			defer func() {
				if r := recover(); r != nil {
					obs.Default().Error("repl.dispatch_turn.panic",
						"panic", r,
						"stack", string(debug.Stack()))
					res = turnResult{err: fmt.Errorf("agent panicked: %v", r)}
				}
				releaseTurn()
				turnDone <- res
			}()
			res.response, res.err = ai.Run(turnCtx, input)
		}()
	}

	deps.busy = func() bool { return ed.running.Load() }

	// --- Filesystem watch (optional) ---
	// --watch flags take precedence over config.watch.paths; both fold into
	// the same rule set. A goroutine consumes the handler channel and forwards
	// events as REPL turns when the agent is idle, so an FS-triggered prompt
	// never collides with a user prompt mid-flight. Queue depth is bounded —
	// bursts beyond the cap drop events rather than growing unbounded.
	watchMgr, stopWatch := startWatch(ctx, deps, dispatchTurn)
	deps.watchMgr = watchMgr
	defer stopWatch()

	ed.render()

	// handleSubmit is invoked when the user presses Enter. Returns true
	// when the REPL should exit.
	handleSubmit := func(raw string) bool {
		input := strings.TrimSpace(raw)

		if input == "" && deps.voiceMode {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● Recording...%s (stops on silence)\n", red, reset)
			})
			// Record into a per-invocation directory created with
			// 0700 — the previous /tmp/promptzero_voice.wav was a
			// world-readable predictable path. Audio captures may
			// contain target/credential content the operator spoke
			// aloud during the session.
			recDir, err := os.MkdirTemp("", "promptzero-voice-*")
			if err != nil {
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● Recording error: %v%s\n", red, err, reset)
				})
				return false
			}
			defer os.RemoveAll(recDir)
			tmpFile := filepath.Join(recDir, "voice.wav")
			if err := voiceEngine.RecordCtx(ctx, tmpFile); err != nil {
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● Recording error: %v%s\n", red, err, reset)
				})
				return false
			}
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● Transcribing...%s\n", blue, reset)
			})
			text, err := voiceEngine.TranscribeCtx(ctx, tmpFile)
			if err != nil {
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● Transcription error: %v%s\n", red, err, reset)
				})
				return false
			}
			// v0.20.0: drop the transcription into the input buffer
			// for an explicit second-Enter confirmation. Previously
			// auto-firing the turn meant a single mis-heard word or
			// stray Enter sent an unintended request to the model;
			// the operator now sees the transcribed text and either
			// edits it or presses Enter again to submit.
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● Transcribed%s — review and press Enter to submit, edit, or Esc to discard\n",
					green, reset)
			})
			ed.insertPaste(text)
			ed.render()
			return false
		}

		if input == "" {
			return false
		}

		if handled, exit := dispatchSlashCommand(input, deps); handled {
			return exit
		}

		if ed.running.Load() {
			ed.setQueued(input)
			ed.writeOutput(func() {
				pad := strings.Repeat(" ", boxPad)
				fmt.Fprintf(os.Stderr, "\n%s%s>%s %s%s %s(queued)%s\n",
					pad, dim, reset, dim, input, dim, reset)
			})
			return false
		}
		dispatchTurn(input)
		return false
	}

	for {
		select {
		case k, ok := <-keys:
			if !ok {
				return nil
			}
			// Hijack keystrokes when a risk confirmation is pending.
			// The line editor stays in whatever state it was in; it is
			// redrawn after the callback resolves.
			if cs := pendingConfirm.Load(); cs != nil {
				if resolveConfirmKey(cs, k, ed) {
					pendingConfirm.Store(nil)
				}
				continue
			}
			// In reverse-i-search mode, runes / Backspace / Enter / Esc-ish
			// keys behave differently — they build the query, accept, or
			// cancel rather than mutate the buffer directly. Routing
			// these here keeps the normal key flow below uncluttered.
			if ed.searching {
				switch k.kind {
				case keyRune:
					ed.runeInSearch(k.r)
					ed.render()
					continue
				case keyBackspace:
					ed.backspaceInSearch()
					ed.render()
					continue
				case keyCtrlR:
					ed.cycleHistorySearchOlder()
					ed.render()
					continue
				case keyEnter:
					ed.acceptSearch()
					ed.render()
					continue
				case keyCtrlC, keyCtrlD, keyCtrlG:
					// Ctrl+G during history search cancels the
					// search (matching the documented contract in
					// lineedit.cancelSearch). Without this case
					// Ctrl+G fell through to the main switch and
					// armed the stream-abort flag — which would
					// then fire against whatever streaming tool
					// ran next, even though the operator was just
					// trying to back out of an i-search.
					ed.cancelSearch()
					ed.render()
					continue
				default:
					// Any other key (arrow, Ctrl+W, Ctrl+K, …)
					// accepts the current search match (matching
					// the bash/zsh readline convention) and then
					// falls through to the main switch so the key
					// applies to the now-current line. Without this
					// default the editor stayed in a hybrid state
					// where ed.searching was true but the main
					// switch had already mutated the buffer — the
					// next rune would unexpectedly land in
					// runeInSearch instead of the buffer.
					ed.acceptSearch()
					// no continue — fall through to main switch
				}
			}
			switch k.kind {
			case keyEOF:
				return nil
			case keyRune:
				ed.insert(k.r)
				ed.render()
			case keyPaste:
				ed.insertPaste(k.text)
				ed.render()
			case keyEnter:
				s := ed.takeInput()
				ed.render()
				if handleSubmit(s) {
					return nil
				}
			case keyBackspace:
				ed.backspace()
				ed.render()
			case keyCtrlW:
				ed.deleteWord()
				ed.render()
			case keyCtrlK:
				ed.killToEnd()
				ed.render()
			case keyCtrlR:
				ed.startHistorySearch()
				ed.render()
			case keyDelete:
				ed.deleteForward()
				ed.render()
			case keyLeft:
				ed.moveLeft()
				ed.render()
			case keyRight:
				ed.moveRight()
				ed.render()
			case keyHome, keyCtrlA:
				ed.moveHome()
				ed.render()
			case keyEnd, keyCtrlE:
				ed.moveEnd()
				ed.render()
			case keyUp:
				ed.browseHistory(-1)
				ed.render()
			case keyDown:
				ed.browseHistory(+1)
				ed.render()
			case keyCtrlL:
				ed.clearScreen()
			case keyCtrlG:
				// Abort the current streaming tool (if one is
				// running). The next frame's stream callback
				// observes the flag, returns false, and the
				// agent's dispatcher fires sink.Abort() + ctx
				// cancel.
				//
				// At idle (no turn running) Ctrl+G is a no-op
				// with a "nothing to stop" hint instead of
				// silently latching the flag — the latch is
				// reset on dispatchTurn start anyway, but
				// showing "stop requested" when there's nothing
				// to stop misleads the operator.
				if !ed.running.Load() {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "\n  %s(nothing to stop — Ctrl+G aborts a streaming tool mid-turn)%s\n", dim, reset)
					})
					break
				}
				streamAbortRequested.Store(true)
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "\n  %s(stop requested — Ctrl+C cancels the whole turn instead)%s\n", dim, reset)
				})
			case keyCtrlC:
				now := time.Now().UnixNano()
				prev := kbdCtrlCAt.Swap(now)
				if prev != 0 && time.Duration(now-prev) < signalDoubleTapWindow {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "\n  %sGoodbye.%s\n\n", dim, reset)
					})
					return nil
				}
				sh.cancelCurrent()
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "\n  %s(Ctrl+C again within 2s to exit)%s\n", dim, reset)
				})
			case keyCtrlD:
				if len(ed.buf) == 0 {
					ed.writeOutput(func() {
						fmt.Fprintf(os.Stderr, "\n  %sShutting down.%s\n\n", dim, reset)
					})
					return nil
				}
			}
		case r := <-turnDone:
			ed.running.Store(false)
			_ = flip.SetLED("b", 0)
			streamed := streaming.Swap(false)
			// Close any in-flight delta stream first so subsequent atomic
			// writes land on a fresh row instead of racing writeDelta's
			// save/restore cursor.
			if streamed {
				ed.endDelta()
			}
			ed.writeOutput(func() {
				if r.err != nil {
					fmt.Fprintf(os.Stderr, "  %s● Error: %v%s\n\n", red, r.err, reset)
				} else if streamed {
					// Response already rendered via text deltas; separator.
					fmt.Fprintf(os.Stderr, "\n")
				} else {
					fmt.Fprintf(os.Stdout, "\n%s\n\n", r.response)
				}
			})
			if q, ok := ed.popQueued(); ok {
				ed.render()
				dispatchTurn(q)
			}
		}
	}
}

// startWatch wires up the optional filesystem watcher. Returns the
// Watcher (nil when no paths are configured) and a stop fn the REPL
// defers; the stop fn cancels the watcher's context so the background
// goroutines exit cleanly before enterREPL returns.
func startWatch(ctx context.Context, deps *REPLDeps, dispatchTurn func(string)) (*watch.Watcher, func()) {
	ed := deps.ed
	cfg := deps.cfg
	paths := append([]string(nil), deps.watchPaths...)
	paths = append(paths, cfg.Watch.Paths...)
	var rules []watch.Rule
	for _, r := range cfg.Watch.Rules {
		if err := watch.ValidatePattern(r.Pattern); err != nil {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● watch: skipping rule with malformed pattern %q: %v%s\n",
					yellow, r.Pattern, err, reset)
			})
			continue
		}
		// Validate the persona reference at startup: a typo'd name
		// would silently no-op at fire time (the lookup at the
		// dispatcher uses `p, ok := personas.Get(name); ok`),
		// leaving the operator wondering why their watch trigger
		// didn't switch persona. Warn-and-continue so the rule still
		// fires with the active persona, matching the pattern-check
		// soft-fail above.
		if r.Persona != "" && deps.personas != nil {
			if _, ok := deps.personas.Get(r.Persona); !ok {
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr,
						"  %s● watch: rule for %q references unknown persona %q (will fire with active persona)%s\n",
						yellow, r.Pattern, r.Persona, reset)
				})
			}
		}
		rules = append(rules, watch.Rule{Pattern: r.Pattern, Prompt: r.Prompt, Persona: r.Persona})
	}
	// Default rule set only applies when the operator asked for --watch
	// but didn't supply config rules — gives the feature sensible defaults
	// without surprising users who configured it explicitly.
	if len(paths) > 0 && len(rules) == 0 {
		rules = []watch.Rule{
			{Pattern: "*.sub", Prompt: "A new Sub-GHz capture landed at {{path}}. Decode it and summarise protocol + key data."},
			{Pattern: "*.nfc", Prompt: "A new NFC capture landed at {{path}}. Identify type, UID, sectors."},
			{Pattern: "*.rfid", Prompt: "A new RFID capture landed at {{path}}. Report protocol and UID."},
			{Pattern: "*.png", Prompt: "Analyze {{path}} — what Flipper-relevant thing is this?"},
			{Pattern: "*.jpg", Prompt: "Analyze {{path}} — what Flipper-relevant thing is this?"},
			{Pattern: "*.txt", Prompt: "Validate {{path}} as a BadUSB payload and summarise what it does."},
		}
	}
	if len(paths) == 0 {
		return nil, func() {}
	}
	watchMgr := watch.New(paths, rules)
	events := make(chan struct {
		rule watch.Rule
		path string
	}, 16)
	watchCtx, cancelWatch := context.WithCancel(ctx)
	obs.SafeGo("repl.watch.fsnotify", func() {
		if err := watchMgr.Run(watchCtx, func(r watch.Rule, p string) error {
			select {
			case events <- struct {
				rule watch.Rule
				path string
			}{r, p}:
			default:
				// Queue full — record and move on rather than blocking
				// the fsnotify goroutine. Bursts of 16+ events in the
				// debounce window are the only way this trips.
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● watch queue full; dropping %s%s\n", yellow, p, reset)
				})
			}
			return nil
		}); err != nil {
			ed.writeOutput(func() {
				fmt.Fprintf(os.Stderr, "  %s● watch error: %v%s\n", red, err, reset)
			})
		}
	})
	obs.SafeGo("repl.watch.dispatcher", func() {
		for {
			select {
			case <-watchCtx.Done():
				return
			case ev := <-events:
				// Wait until the REPL is idle before dispatching so
				// user turns and watch turns don't interleave.
				for ed.running.Load() {
					select {
					case <-watchCtx.Done():
						return
					case <-time.After(250 * time.Millisecond):
					}
				}
				if ev.rule.Persona != "" {
					if p, ok := deps.personas.Get(ev.rule.Persona); ok {
						deps.ai.SetPersona(p)
					}
				}
				ed.writeOutput(func() {
					fmt.Fprintf(os.Stderr, "  %s● watch fired:%s %s %s→%s %s\n",
						yellow, reset, ev.path, dim, reset, collapseWS(ev.rule.Prompt))
				})
				dispatchTurn(ev.rule.Prompt)
			}
		}
	})
	statusOK(fmt.Sprintf("Watch active on %s%d path%s%s", bold, len(paths), plural(len(paths)), reset))
	return watchMgr, cancelWatch
}
