package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"
)

// keyKind enumerates the logical keystrokes the editor reacts to.
type keyKind int

const (
	keyRune keyKind = iota
	keyEnter
	keyBackspace
	keyDelete
	keyLeft
	keyRight
	keyUp
	keyDown
	keyHome
	keyEnd
	keyCtrlA
	keyCtrlE
	keyCtrlC
	keyCtrlD
	keyCtrlL
	keyEOF
	// keyPaste carries a bracketed-paste payload in text. Literal bytes
	// (including \r/\n) are preserved so pastes never auto-submit — the
	// user still has to press Enter themselves.
	keyPaste
)

type keyEvent struct {
	kind keyKind
	r    rune
	text string // populated for keyPaste only
}

// Bracketed-paste markers (DECSET 2004). The terminal wraps a paste in
// these sequences so we can buffer the payload as literal bytes instead of
// processing each byte as if the user typed it.
var (
	pasteStart = []byte{0x1b, '[', '2', '0', '0', '~'}
	pasteEnd   = []byte{0x1b, '[', '2', '0', '1', '~'}
)

// readKeys reads raw stdin and emits parsed keystroke events on out.
// Runs until stdin closes or returns an error. Caller closes out when done.
func readKeys(out chan<- keyEvent) {
	defer close(out)
	buf := make([]byte, 64)
	// carry holds leftover bytes from the previous read — either an
	// in-progress escape sequence at the end of the last buffer, or the
	// payload we've accumulated while inside a bracketed paste.
	var carry []byte
	inPaste := false
	var pasteBuf []byte
	for {
		n, err := os.Stdin.Read(buf)
		if err != nil || n == 0 {
			out <- keyEvent{kind: keyEOF}
			return
		}
		data := buf[:n]
		if len(carry) > 0 {
			data = append(carry, data...)
			carry = carry[:0]
		}
		i := 0
		for i < len(data) {
			if inPaste {
				// Look for the paste-end marker somewhere in the remaining
				// bytes. Anything before it is literal paste content.
				if idx := indexOf(data[i:], pasteEnd); idx >= 0 {
					pasteBuf = append(pasteBuf, data[i:i+idx]...)
					out <- keyEvent{kind: keyPaste, text: string(pasteBuf)}
					pasteBuf = pasteBuf[:0]
					inPaste = false
					i += idx + len(pasteEnd)
					continue
				}
				// No end marker yet — append as much as is safe and stash
				// the tail so a partial end sequence doesn't leak out.
				safe := len(data) - i - (len(pasteEnd) - 1)
				if safe < 0 {
					safe = 0
				}
				if safe > 0 {
					pasteBuf = append(pasteBuf, data[i:i+safe]...)
					i += safe
				}
				carry = append(carry[:0], data[i:]...)
				break
			}
			b := data[i]
			if b == 0x1b {
				// Check for paste-start first — parseEscape doesn't handle it.
				if hasPrefix(data[i:], pasteStart) {
					inPaste = true
					i += len(pasteStart)
					continue
				}
				if adv, ev, ok := parseEscape(data[i:]); ok {
					out <- ev
					i += adv
					continue
				}
				// Possibly a partial escape at end of buffer — stash for next read.
				if len(data)-i < 6 {
					carry = append(carry[:0], data[i:]...)
					break
				}
				// Bare ESC — swallow. Partial sequences are rare over a local TTY;
				// if they ever happen we'd lose one keystroke, not crash.
				i++
				continue
			}
			switch b {
			case 0x01:
				out <- keyEvent{kind: keyCtrlA}
				i++
			case 0x03:
				out <- keyEvent{kind: keyCtrlC}
				i++
			case 0x04:
				out <- keyEvent{kind: keyCtrlD}
				i++
			case 0x05:
				out <- keyEvent{kind: keyCtrlE}
				i++
			case 0x08, 0x7f:
				out <- keyEvent{kind: keyBackspace}
				i++
			case 0x0a, 0x0d:
				out <- keyEvent{kind: keyEnter}
				i++
			case 0x0c:
				out <- keyEvent{kind: keyCtrlL}
				i++
			default:
				if b < 0x20 {
					i++
					continue
				}
				if b < 0x80 {
					out <- keyEvent{kind: keyRune, r: rune(b)}
					i++
					continue
				}
				r, size := utf8.DecodeRune(data[i:])
				if r == utf8.RuneError && size == 1 {
					// Possibly a truncated UTF-8 sequence — stash for next read.
					if len(data)-i < 4 {
						carry = append(carry[:0], data[i:]...)
						i = len(data)
						break
					}
					i++
					continue
				}
				out <- keyEvent{kind: keyRune, r: r}
				i += size
			}
		}
	}
}

// hasPrefix reports whether b starts with prefix.
func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}

// indexOf returns the index of sep in b, or -1 if absent.
func indexOf(b, sep []byte) int {
	if len(sep) == 0 {
		return 0
	}
	for i := 0; i+len(sep) <= len(b); i++ {
		if hasPrefix(b[i:], sep) {
			return i
		}
	}
	return -1
}

// parseEscape consumes an ANSI escape sequence starting at b[0]==0x1b.
// Returns the number of bytes consumed, the parsed event, and whether
// the sequence was recognized. Unknown sequences return ok=false and
// the caller drops the ESC byte.
func parseEscape(b []byte) (int, keyEvent, bool) {
	if len(b) < 3 || b[1] != '[' {
		return 0, keyEvent{}, false
	}
	switch b[2] {
	case 'A':
		return 3, keyEvent{kind: keyUp}, true
	case 'B':
		return 3, keyEvent{kind: keyDown}, true
	case 'C':
		return 3, keyEvent{kind: keyRight}, true
	case 'D':
		return 3, keyEvent{kind: keyLeft}, true
	case 'H':
		return 3, keyEvent{kind: keyHome}, true
	case 'F':
		return 3, keyEvent{kind: keyEnd}, true
	case '1', '7':
		if len(b) >= 4 && b[3] == '~' {
			return 4, keyEvent{kind: keyHome}, true
		}
	case '4', '8':
		if len(b) >= 4 && b[3] == '~' {
			return 4, keyEvent{kind: keyEnd}, true
		}
	case '3':
		if len(b) >= 4 && b[3] == '~' {
			return 4, keyEvent{kind: keyDelete}, true
		}
	}
	return 0, keyEvent{}, false
}

// lineEditor owns the in-memory input buffer and renders it into the
// persistent input box drawn by termUI. The main REPL goroutine is the
// sole writer of buf/cursor; the reader goroutine only emits keyEvents.
type lineEditor struct {
	ui *termUI

	// outputMu serializes every write to stderr so keystroke redraws,
	// tool-status callbacks, and turn output don't scribble over each
	// other. Acquire before any Fprintf to stderr.
	outputMu sync.Mutex

	buf    []rune
	cursor int // index in buf, 0..len(buf)
	offset int // first visible rune when buf exceeds slot width

	history    []string
	historyIdx int    // -1 when not browsing
	savedEdit  []rune // buffer stashed while browsing history

	// Queued prompt — single slot. If the user presses Enter while a turn
	// is running, the new input replaces whatever is queued. Documented.
	hasQueued atomic.Bool
	queuedMu  sync.Mutex
	queued    string

	// running is true while a turn is in flight. Read by submit() to
	// decide queue-vs-dispatch; written by the REPL around ai.Run.
	running atomic.Bool

	// streaming is true while writeDelta is shepherding LLM text into the
	// scroll region. Protected by outputMu. See writeDelta/endDelta.
	streaming bool
}

const maxHistory = 50

func newLineEditor(ui *termUI) *lineEditor {
	return &lineEditor{ui: ui, historyIdx: -1}
}

// --- buffer mutations (main goroutine only) -----------------------------

func (e *lineEditor) detachHistory() {
	e.historyIdx = -1
	e.savedEdit = nil
}

func (e *lineEditor) insert(r rune) {
	e.detachHistory()
	next := make([]rune, 0, len(e.buf)+1)
	next = append(next, e.buf[:e.cursor]...)
	next = append(next, r)
	next = append(next, e.buf[e.cursor:]...)
	e.buf = next
	e.cursor++
}

// insertPaste inserts a bracketed-paste payload as literal characters. CR
// and LF become a visible "↵" marker so the user can see multi-line
// structure; a bare Enter is still required to submit — pastes never auto-
// submit on their own.
func (e *lineEditor) insertPaste(text string) {
	e.detachHistory()
	if text == "" {
		return
	}
	runes := make([]rune, 0, len(text))
	for _, r := range text {
		switch r {
		case '\r':
			// Collapse CRLF into a single marker; a lone CR also becomes one.
			runes = append(runes, '↵')
		case '\n':
			if len(runes) > 0 && runes[len(runes)-1] == '↵' {
				continue
			}
			runes = append(runes, '↵')
		case '\t':
			runes = append(runes, ' ', ' ', ' ', ' ')
		default:
			if r < 0x20 {
				continue
			}
			runes = append(runes, r)
		}
	}
	if len(runes) == 0 {
		return
	}
	next := make([]rune, 0, len(e.buf)+len(runes))
	next = append(next, e.buf[:e.cursor]...)
	next = append(next, runes...)
	next = append(next, e.buf[e.cursor:]...)
	e.buf = next
	e.cursor += len(runes)
}

func (e *lineEditor) backspace() {
	e.detachHistory()
	if e.cursor == 0 {
		return
	}
	e.buf = append(e.buf[:e.cursor-1], e.buf[e.cursor:]...)
	e.cursor--
}

func (e *lineEditor) deleteForward() {
	e.detachHistory()
	if e.cursor >= len(e.buf) {
		return
	}
	e.buf = append(e.buf[:e.cursor], e.buf[e.cursor+1:]...)
}

func (e *lineEditor) moveLeft() {
	if e.cursor > 0 {
		e.cursor--
	}
}

func (e *lineEditor) moveRight() {
	if e.cursor < len(e.buf) {
		e.cursor++
	}
}

func (e *lineEditor) moveHome() { e.cursor = 0 }

func (e *lineEditor) moveEnd() { e.cursor = len(e.buf) }

// browseHistory moves through the history ring. delta=-1 goes older,
// delta=+1 goes newer. Past the newest entry the buffer is restored to
// whatever the user was typing before they started browsing.
func (e *lineEditor) browseHistory(delta int) {
	if len(e.history) == 0 {
		return
	}
	if e.historyIdx == -1 {
		e.savedEdit = append([]rune(nil), e.buf...)
		e.historyIdx = len(e.history)
	}
	next := e.historyIdx + delta
	if next < 0 {
		next = 0
	}
	if next > len(e.history) {
		next = len(e.history)
	}
	if next == len(e.history) {
		e.buf = append([]rune(nil), e.savedEdit...)
		e.historyIdx = -1
		e.savedEdit = nil
	} else {
		e.buf = []rune(e.history[next])
		e.historyIdx = next
	}
	e.cursor = len(e.buf)
	e.offset = 0
}

// takeInput returns the current buffer contents, clears the buffer,
// and adds the submission to history (if non-empty and not a duplicate
// of the most recent entry). Paste newline markers (↵) are translated
// back to real newlines so the consumer sees the original structure.
func (e *lineEditor) takeInput() string {
	raw := string(e.buf)
	s := strings.ReplaceAll(raw, "↵", "\n")
	e.buf = e.buf[:0]
	e.cursor = 0
	e.offset = 0
	e.detachHistory()
	if trimmed := strings.TrimSpace(s); trimmed != "" {
		if len(e.history) == 0 || e.history[len(e.history)-1] != s {
			e.history = append(e.history, s)
			if len(e.history) > maxHistory {
				e.history = e.history[len(e.history)-maxHistory:]
			}
		}
	}
	return s
}

// --- queue (writable from multiple goroutines) --------------------------

// setQueued overwrites the single-slot queue. Last-write-wins: if the
// user presses Enter repeatedly while a turn runs, only the most recent
// prompt is kept.
func (e *lineEditor) setQueued(s string) {
	e.queuedMu.Lock()
	e.queued = s
	e.hasQueued.Store(true)
	e.queuedMu.Unlock()
}

func (e *lineEditor) popQueued() (string, bool) {
	if !e.hasQueued.Load() {
		return "", false
	}
	e.queuedMu.Lock()
	s := e.queued
	e.queued = ""
	// Flip the flag inside the lock so a concurrent setQueued can't write
	// a new entry between our read and the flag clear — which would have
	// left hasQueued==false with a live item in e.queued.
	e.hasQueued.Store(false)
	e.queuedMu.Unlock()
	return s, true
}

// --- rendering -----------------------------------------------------------

const queuedLabel = "(1 queued)"

// render is the locked entry point — safe to call from any goroutine.
// renderLocked is for callers that already hold outputMu.
func (e *lineEditor) render() {
	e.outputMu.Lock()
	defer e.outputMu.Unlock()
	e.renderLocked()
}

func (e *lineEditor) renderLocked() {
	if !e.ui.enabled {
		return
	}
	rows, cols := e.ui.Rows(), e.ui.Cols()
	width := cols - boxPad
	inner := width - 2
	// After "│ > " (left border + 3 prompt chars) and before right │.
	slot := inner - 3
	if slot < 4 {
		return
	}

	// Reserve space at the right for the queued marker if present.
	markerW := 0
	if e.hasQueued.Load() {
		// " (1 queued)" — one leading space so it doesn't butt against input
		markerW = 1 + len(queuedLabel)
		if markerW > slot/2 {
			markerW = 0 // slot too narrow, skip marker
		}
	}
	typing := slot - markerW
	if typing < 4 {
		typing = slot
		markerW = 0
	}

	// Horizontal scroll so cursor sits inside [offset, offset+typing).
	if e.cursor < e.offset {
		e.offset = e.cursor
	}
	if e.cursor >= e.offset+typing {
		e.offset = e.cursor - typing + 1
	}
	if e.offset < 0 {
		e.offset = 0
	}

	end := e.offset + typing
	if end > len(e.buf) {
		end = len(e.buf)
	}
	vis := make([]rune, end-e.offset)
	copy(vis, e.buf[e.offset:end])
	// Ellipsis glyphs when content is scrolled out of view. Cursor may
	// visually overlap the ellipsis at the edges; the glyph still shows
	// because the terminal cursor renders on top.
	if e.offset > 0 && len(vis) > 0 {
		vis[0] = '…'
	}
	if end < len(e.buf) && len(vis) > 0 {
		vis[len(vis)-1] = '…'
	}
	disp := string(vis)

	padTypingCount := typing - len(vis)
	if padTypingCount < 0 {
		padTypingCount = 0
	}
	typingPad := strings.Repeat(" ", padTypingCount)

	var marker string
	if markerW > 0 {
		marker = " " + dim + queuedLabel + reset
	} else if e.hasQueued.Load() {
		// Fallback: no room for full label, cram a tiny hint.
		marker = dim + "⏎" + reset
		// Not counted in markerW so the right border may shift by one — acceptable.
	}

	pad := strings.Repeat(" ", boxPad)

	// Full input line: <pad>│ > <typing slot><marker>│
	fmt.Fprintf(os.Stderr, "\033[%d;1H\033[2K%s%s%s%s %s>%s %s%s%s%s%s%s",
		rows-1, pad,
		dim, boxV, reset,
		bold+red, reset,
		disp, typingPad,
		marker,
		dim, boxV, reset,
	)

	// Park the cursor at the logical buffer position.
	// Column math: pad occupies cols 1..boxPad; │ at boxPad+1; space at +2;
	// > at +3; space at +4; first slot char at boxPad+5.
	cursorCol := boxPad + 5 + (e.cursor - e.offset)
	fmt.Fprintf(os.Stderr, "\033[%d;%dH", rows-1, cursorCol)
}

// writeOutput runs fn with outputMu held and redraws the input line
// afterwards so any terminal output lands in the scroll region without
// leaving the input box in a stale state. Use for atomic, one-shot writes
// (status lines, tool-call start/finish, slash-command output). For
// streamed LLM text deltas use writeDelta instead — writeOutput would
// reset the cursor to column 1 on every chunk, overwriting the previous
// one.
func (e *lineEditor) writeOutput(fn func()) {
	e.outputMu.Lock()
	defer e.outputMu.Unlock()
	// An in-flight stream reserves the cursor position at the bottom of
	// the scroll region; flush a newline and close the stream before any
	// atomic write so the two don't collide on the same row.
	if e.streaming {
		fmt.Fprint(os.Stderr, "\033[u\n\033[s")
		e.streaming = false
	}
	if e.ui.enabled {
		e.ui.positionOutput()
	}
	fn()
	e.renderLocked()
}

// writeDelta appends a chunk of streamed assistant text to the scroll
// region, preserving the cursor position between chunks so successive
// tokens flow across lines naturally instead of clobbering each other at
// column 1 (writeOutput's behaviour). Uses DEC save-cursor (\033[s) and
// restore-cursor (\033[u) to round-trip through the input-line redraw.
//
// Invariants:
//   - Caller should not interleave writeDelta with writeOutput for the
//     same logical stream. writeOutput's streaming check handles that
//     case defensively but the rendering will show a line break.
//   - endDelta must be called at stream end so a subsequent atomic write
//     starts on a fresh row.
func (e *lineEditor) writeDelta(text string) {
	e.outputMu.Lock()
	defer e.outputMu.Unlock()
	if !e.ui.enabled {
		// Non-TTY path: just write, no cursor games.
		fmt.Fprint(os.Stderr, text)
		return
	}
	if !e.streaming {
		// First chunk of a new stream: park cursor at the bottom of the
		// scroll region, then immediately save that as our anchor.
		e.ui.positionOutput()
		fmt.Fprint(os.Stderr, "\033[s")
		e.streaming = true
	} else {
		// Restore cursor to the end of the previous chunk.
		fmt.Fprint(os.Stderr, "\033[u")
	}
	fmt.Fprint(os.Stderr, text)
	// Save the new end-of-stream position, then redraw the input line
	// (which moves the cursor off to row-1; the next delta will restore).
	fmt.Fprint(os.Stderr, "\033[s")
	e.renderLocked()
}

// endDelta finalises a streaming run: emits a newline so the next atomic
// write starts cleanly, clears the streaming flag, redraws the input
// line. Safe to call when no stream is active — it's a no-op.
func (e *lineEditor) endDelta() {
	e.outputMu.Lock()
	defer e.outputMu.Unlock()
	if !e.streaming {
		return
	}
	if e.ui.enabled {
		// Restore to end of last chunk, emit newline, save (so any stray
		// writer that checks streaming won't overwrite), then redraw box.
		fmt.Fprint(os.Stderr, "\033[u\n\033[s")
	} else {
		fmt.Fprintln(os.Stderr)
	}
	e.streaming = false
	e.renderLocked()
}

// clearScreen wipes everything outside the box and redraws the box
// frame. Scroll region stays configured. A dim hint reminds the user
// that the conversation is still in memory — /reset is what actually
// forgets it.
func (e *lineEditor) clearScreen() {
	e.outputMu.Lock()
	defer e.outputMu.Unlock()
	if !e.ui.enabled {
		return
	}
	fmt.Fprint(os.Stderr, "\033[2J")
	e.ui.drawBoxFrame()
	e.ui.positionOutput()
	pad := strings.Repeat(" ", boxPad)
	fmt.Fprintf(os.Stderr, "%s%s(screen cleared — conversation still active, use /reset to forget)%s\n",
		pad, dim, reset)
	e.renderLocked()
}
