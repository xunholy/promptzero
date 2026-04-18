package main

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"golang.org/x/term"
)

// Input box glyphs — a full rounded rectangle around the current prompt.
// Typed input lives inside; past prompts demote to a single dim "> ..." line.
const (
	boxTL   = "╭"
	boxTR   = "╮"
	boxBL   = "╰"
	boxBR   = "╯"
	boxV    = "│"
	boxRule = "─"
	boxPad  = 2 // leading spaces before the left border
)

// boxHeight is the number of rows reserved for the persistent input box
// at the bottom of the terminal.
const boxHeight = 3

// termUI owns a persistent 3-line input box pinned to the bottom of the
// terminal. The area above (a DEC scroll region) carries all agent/tool
// output; the box is redrawn once at setup and only the input line is
// refreshed after each Enter, so the box visually stays put while output
// scrolls past it. Not a full TUI, but gets the Claude-Code feel without
// a TUI framework.
//
// rows/cols are atomics so the SIGWINCH handler can update them from a
// signal goroutine while the render path reads them. The render path
// still serialises against outputMu — the atomics only cover the
// dimension reads/writes themselves.
type termUI struct {
	rows    atomic.Int32
	cols    atomic.Int32
	enabled bool
}

// newTermUI probes stdout for TTY state and size. Returns a disabled UI
// when stdout isn't a terminal or the window is too small to host the
// input box.
func newTermUI() *termUI {
	if !term.IsTerminal(int(os.Stdout.Fd())) {
		return &termUI{enabled: false}
	}
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || rows < 8 || cols < 24 {
		return &termUI{enabled: false}
	}
	ui := &termUI{enabled: true}
	ui.rows.Store(int32(rows))
	ui.cols.Store(int32(cols))
	return ui
}

// Rows returns the current terminal row count. Updated by the SIGWINCH
// handler; safe to call from any goroutine.
func (t *termUI) Rows() int { return int(t.rows.Load()) }

// Cols returns the current terminal column count. Updated by the SIGWINCH
// handler; safe to call from any goroutine.
func (t *termUI) Cols() int { return int(t.cols.Load()) }

// resize reads the current terminal size and updates rows/cols. Returns
// whether the dimensions actually changed. Caller owns redrawing.
func (t *termUI) resize() bool {
	if !t.enabled {
		return false
	}
	cols, rows, err := term.GetSize(int(os.Stdout.Fd()))
	if err != nil || rows < 8 || cols < 24 {
		return false
	}
	changed := int(t.rows.Load()) != rows || int(t.cols.Load()) != cols
	t.rows.Store(int32(rows))
	t.cols.Store(int32(cols))
	return changed
}

// setup carves a DEC scroll region above the box and paints the initial
// border + empty input line. No-op when the UI is disabled.
func (t *termUI) setup() {
	if !t.enabled {
		return
	}
	rows := t.Rows()
	fmt.Fprintf(os.Stderr, "\033[1;%dr", rows-boxHeight)
	t.drawBoxFrame()
	t.drawInputLineEmpty()
	fmt.Fprintf(os.Stderr, "\033[%d;1H", rows-boxHeight)
}

// teardown clears the scroll region and returns the cursor to the bottom
// row so the next shell prompt lands on a clean line.
func (t *termUI) teardown() {
	if !t.enabled {
		return
	}
	fmt.Fprint(os.Stderr, "\033[r")
	fmt.Fprintf(os.Stderr, "\033[%d;1H\n", t.Rows())
}

// positionOutput parks the cursor at the first row of the scroll region
// so stray writes land above the box, not inside it.
func (t *termUI) positionOutput() {
	if !t.enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[%d;1H", t.Rows()-boxHeight)
}

// positionInput parks the cursor at the first slot of the editable
// input line inside the box.
func (t *termUI) positionInput() {
	if !t.enabled {
		return
	}
	fmt.Fprintf(os.Stderr, "\033[%d;%dH", t.Rows()-1, boxPad+4+1)
}

// drawBoxFrame paints the top and bottom borders of the input box at
// the current terminal size.
func (t *termUI) drawBoxFrame() {
	rows, cols := t.Rows(), t.Cols()
	width := cols - boxPad
	inner := width - 2
	rule := strings.Repeat(boxRule, inner)
	pad := strings.Repeat(" ", boxPad)
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
		rows-2, pad, dim, boxTL, rule, boxTR, reset)
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
		rows, pad, dim, boxBL, rule, boxBR, reset)
}

// drawStatusBorder redraws the box's top border. Empty status → plain rule
// of dashes (idle). Non-empty → status embedded inside the border like
// "╭── ⠙ Thinking · 5s · Ctrl+C to interrupt ───╮" so the user always has
// a visible turn-in-flight indicator without reserving an extra row.
func (t *termUI) drawStatusBorder(status string) {
	if !t.enabled {
		return
	}
	rows, cols := t.Rows(), t.Cols()
	width := cols - boxPad
	inner := width - 2
	pad := strings.Repeat(" ", boxPad)

	if status == "" {
		rule := strings.Repeat(boxRule, inner)
		fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
			rows-2, pad, dim, boxTL, rule, boxTR, reset)
		return
	}

	const leading = 2
	runes := []rune(status)
	avail := inner - leading - 2 // 2 spaces around the status text
	if avail < 1 {
		rule := strings.Repeat(boxRule, inner)
		fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s%s",
			rows-2, pad, dim, boxTL, rule, boxTR, reset)
		return
	}
	if len(runes) > avail {
		runes = append(runes[:avail-1], '…')
	}
	trailing := inner - leading - 2 - len(runes)
	if trailing < 0 {
		trailing = 0
	}

	// Layout: pad + dim(╭──) + " " + status + " " + dim(──╮) + reset
	// — status renders in the default style so it reads bright against the
	// dimmed border dashes.
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s%s %s %s%s%s%s",
		rows-2,
		pad,
		dim, boxTL, strings.Repeat(boxRule, leading), reset,
		string(runes),
		dim, strings.Repeat(boxRule, trailing), boxTR, reset,
	)
}

// drawInputLineEmpty paints the middle row of the box with a red ">" and
// blank space for the editable prompt.
func (t *termUI) drawInputLineEmpty() {
	if !t.enabled {
		return
	}
	rows, cols := t.Rows(), t.Cols()
	width := cols - boxPad
	inner := width - 2
	tailSpaces := strings.Repeat(" ", inner-3)
	pad := strings.Repeat(" ", boxPad)
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s %s>%s %s%s%s%s",
		rows-1, pad, dim, boxV, reset,
		bold+red, reset,
		tailSpaces, dim, boxV, reset)
}
