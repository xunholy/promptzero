package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr runs fn with os.Stderr redirected into a pipe and returns
// everything written during the call. Used by the streaming tests which
// need to inspect the actual byte sequence going to the terminal.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	fn()
	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return out
}

func newTestEditor() *lineEditor {
	return newLineEditor(&termUI{enabled: false})
}

func TestInsertAdvancesCursor(t *testing.T) {
	e := newTestEditor()
	for _, r := range "hello" {
		e.insert(r)
	}
	if got, want := string(e.buf), "hello"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
	if e.cursor != 5 {
		t.Fatalf("cursor = %d, want 5", e.cursor)
	}
}

func TestInsertAtCursor(t *testing.T) {
	e := newTestEditor()
	for _, r := range "helo" {
		e.insert(r)
	}
	e.cursor = 3 // between "hel" and "o"
	e.insert('l')
	if got, want := string(e.buf), "hello"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
	if e.cursor != 4 {
		t.Fatalf("cursor = %d, want 4", e.cursor)
	}
}

func TestBackspace(t *testing.T) {
	e := newTestEditor()
	for _, r := range "hello" {
		e.insert(r)
	}
	e.backspace()
	if got, want := string(e.buf), "hell"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
	if e.cursor != 4 {
		t.Fatalf("cursor = %d, want 4", e.cursor)
	}
	// Backspace at start is a no-op.
	e.cursor = 0
	e.backspace()
	if got, want := string(e.buf), "hell"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
}

func TestDeleteForward(t *testing.T) {
	e := newTestEditor()
	for _, r := range "hello" {
		e.insert(r)
	}
	e.cursor = 0
	e.deleteForward()
	if got, want := string(e.buf), "ello"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
	// Delete at end is a no-op.
	e.cursor = len(e.buf)
	e.deleteForward()
	if got, want := string(e.buf), "ello"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
}

func TestCursorBounds(t *testing.T) {
	e := newTestEditor()
	e.moveLeft() // no-op at 0
	if e.cursor != 0 {
		t.Fatalf("cursor = %d, want 0", e.cursor)
	}
	for _, r := range "ab" {
		e.insert(r)
	}
	e.moveRight() // no-op at end
	if e.cursor != 2 {
		t.Fatalf("cursor = %d, want 2", e.cursor)
	}
	e.moveHome()
	if e.cursor != 0 {
		t.Fatalf("cursor = %d, want 0", e.cursor)
	}
	e.moveEnd()
	if e.cursor != 2 {
		t.Fatalf("cursor = %d, want 2", e.cursor)
	}
}

func TestHistoryBrowseSaveAndRestore(t *testing.T) {
	e := newTestEditor()
	e.history = []string{"one", "two", "three"}

	for _, r := range "draft" {
		e.insert(r)
	}
	// Up once — most recent is "three".
	e.browseHistory(-1)
	if got, want := string(e.buf), "three"; got != want {
		t.Fatalf("buf after Up = %q, want %q", got, want)
	}
	// Up again — "two".
	e.browseHistory(-1)
	if got, want := string(e.buf), "two"; got != want {
		t.Fatalf("buf after Up Up = %q, want %q", got, want)
	}
	// Down — "three".
	e.browseHistory(+1)
	if got, want := string(e.buf), "three"; got != want {
		t.Fatalf("buf after Down = %q, want %q", got, want)
	}
	// Down past newest — restores "draft".
	e.browseHistory(+1)
	if got, want := string(e.buf), "draft"; got != want {
		t.Fatalf("buf after Down past newest = %q, want %q", got, want)
	}
	if e.historyIdx != -1 {
		t.Fatalf("historyIdx = %d, want -1", e.historyIdx)
	}
}

func TestHistoryDetachOnType(t *testing.T) {
	e := newTestEditor()
	e.history = []string{"one", "two"}
	e.browseHistory(-1)
	if string(e.buf) != "two" {
		t.Fatalf("expected 'two', got %q", string(e.buf))
	}
	// Typing while browsing detaches, so Down won't restore anything.
	e.insert('!')
	if got, want := string(e.buf), "two!"; got != want {
		t.Fatalf("buf after edit = %q, want %q", got, want)
	}
	if e.historyIdx != -1 {
		t.Fatalf("historyIdx should detach to -1, got %d", e.historyIdx)
	}
}

func TestTakeInputAddsToHistory(t *testing.T) {
	e := newTestEditor()
	for _, r := range "hello" {
		e.insert(r)
	}
	s := e.takeInput()
	if s != "hello" {
		t.Fatalf("takeInput = %q, want %q", s, "hello")
	}
	if len(e.buf) != 0 {
		t.Fatalf("buf not cleared: %q", string(e.buf))
	}
	if e.cursor != 0 {
		t.Fatalf("cursor = %d, want 0", e.cursor)
	}
	if len(e.history) != 1 || e.history[0] != "hello" {
		t.Fatalf("history = %v, want [hello]", e.history)
	}
}

func TestTakeInputDedupesConsecutive(t *testing.T) {
	e := newTestEditor()
	for _, r := range "x" {
		e.insert(r)
	}
	e.takeInput()
	for _, r := range "x" {
		e.insert(r)
	}
	e.takeInput()
	if len(e.history) != 1 {
		t.Fatalf("consecutive duplicate should not grow history: %v", e.history)
	}
}

func TestTakeInputSkipsBlank(t *testing.T) {
	e := newTestEditor()
	for _, r := range "   " {
		e.insert(r)
	}
	e.takeInput()
	if len(e.history) != 0 {
		t.Fatalf("blank submission should not add to history: %v", e.history)
	}
}

func TestHistoryCap(t *testing.T) {
	e := newTestEditor()
	for i := 0; i < maxHistory+10; i++ {
		for _, r := range []rune{'a' + rune(i%26)} {
			e.insert(r)
		}
		// Force unique value so dedupe doesn't kick in.
		e.insert(rune('0' + i%10))
		e.takeInput()
	}
	if len(e.history) != maxHistory {
		t.Fatalf("history length = %d, want %d", len(e.history), maxHistory)
	}
}

func TestQueueSingleSlot(t *testing.T) {
	e := newTestEditor()
	if e.hasQueued.Load() {
		t.Fatalf("fresh editor should not be queued")
	}
	e.setQueued("a")
	e.setQueued("b") // overwrites
	s, ok := e.popQueued()
	if !ok || s != "b" {
		t.Fatalf("popQueued = (%q, %v), want (b, true)", s, ok)
	}
	if e.hasQueued.Load() {
		t.Fatalf("queue should be empty after pop")
	}
	_, ok = e.popQueued()
	if ok {
		t.Fatalf("popQueued on empty queue should return false")
	}
}

func TestParseEscape(t *testing.T) {
	cases := []struct {
		in   []byte
		adv  int
		kind keyKind
	}{
		{[]byte{0x1b, '[', 'A'}, 3, keyUp},
		{[]byte{0x1b, '[', 'B'}, 3, keyDown},
		{[]byte{0x1b, '[', 'C'}, 3, keyRight},
		{[]byte{0x1b, '[', 'D'}, 3, keyLeft},
		{[]byte{0x1b, '[', 'H'}, 3, keyHome},
		{[]byte{0x1b, '[', 'F'}, 3, keyEnd},
		{[]byte{0x1b, '[', '3', '~'}, 4, keyDelete},
		{[]byte{0x1b, '[', '1', '~'}, 4, keyHome},
		{[]byte{0x1b, '[', '4', '~'}, 4, keyEnd},
	}
	for _, c := range cases {
		adv, ev, ok := parseEscape(c.in)
		if !ok {
			t.Errorf("parseEscape(%v) returned ok=false", c.in)
			continue
		}
		if adv != c.adv || ev.kind != c.kind {
			t.Errorf("parseEscape(%v) = (%d, %d), want (%d, %d)",
				c.in, adv, ev.kind, c.adv, c.kind)
		}
	}

	// Truncated sequence — should return ok=false.
	if _, _, ok := parseEscape([]byte{0x1b}); ok {
		t.Errorf("bare ESC should not parse")
	}
	if _, _, ok := parseEscape([]byte{0x1b, '['}); ok {
		t.Errorf("partial CSI should not parse")
	}
}

func TestInsertPasteMultilineBecomesMarker(t *testing.T) {
	e := newTestEditor()
	e.insertPaste("line one\nline two\r\nline three")
	got := string(e.buf)
	want := "line one↵line two↵line three"
	if got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
	// takeInput should translate the marker back to real newlines.
	submitted := e.takeInput()
	if submitted != "line one\nline two\nline three" {
		t.Fatalf("takeInput = %q", submitted)
	}
}

func TestInsertPasteStripsControls(t *testing.T) {
	e := newTestEditor()
	e.insertPaste("abc\x00\x01def")
	if got, want := string(e.buf), "abcdef"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
}

func TestInsertPasteTabExpands(t *testing.T) {
	e := newTestEditor()
	e.insertPaste("a\tb")
	if got, want := string(e.buf), "a    b"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
}

func TestIndexOfAndHasPrefix(t *testing.T) {
	if !hasPrefix([]byte("hello"), []byte("hel")) {
		t.Fatal("hasPrefix should match hel in hello")
	}
	if hasPrefix([]byte("hi"), []byte("hello")) {
		t.Fatal("hasPrefix should not match when src shorter than prefix")
	}
	if idx := indexOf([]byte("abcabcd"), []byte("abcd")); idx != 3 {
		t.Fatalf("indexOf = %d, want 3", idx)
	}
	if idx := indexOf([]byte("abc"), []byte("xyz")); idx != -1 {
		t.Fatalf("indexOf = %d, want -1", idx)
	}
}

func TestQueuePopClearsFlagAtomically(t *testing.T) {
	// Regression: popQueued used to clear hasQueued after releasing the
	// mutex, which opened a window where a concurrent setQueued could write
	// a new item that then got stomped by the late Store(false).
	e := newTestEditor()
	e.setQueued("x")
	_, ok := e.popQueued()
	if !ok {
		t.Fatal("expected popQueued to return ok=true")
	}
	if e.hasQueued.Load() {
		t.Fatal("hasQueued should be false immediately after popQueued")
	}
}

func TestMultibyteRuneInsert(t *testing.T) {
	e := newTestEditor()
	e.insert('é')
	e.insert('🙂')
	if got, want := string(e.buf), "é🙂"; got != want {
		t.Fatalf("buf = %q, want %q", got, want)
	}
	if e.cursor != 2 {
		t.Fatalf("cursor = %d, want 2 (runes)", e.cursor)
	}
	e.backspace()
	if got, want := string(e.buf), "é"; got != want {
		t.Fatalf("buf after backspace = %q, want %q", got, want)
	}
}

// TestWriteDeltaStreamingOrder is the regression guard for the rendering
// bug where streamed text deltas were clobbering each other at column 1
// because writeOutput unconditionally re-positioned the cursor to
// positionOutput on every chunk. The fix (writeDelta) uses DEC save /
// restore cursor so successive chunks append naturally.
//
// We assert the save/restore dance is present between chunks and that no
// chunk is preceded by the column-1 reset sequence that caused the bug.
func TestWriteDeltaStreamingOrder(t *testing.T) {
	ui := &termUI{enabled: true}
	ui.rows.Store(24)
	ui.cols.Store(80)
	e := newLineEditor(ui)

	out := captureStderr(t, func() {
		e.writeDelta("Here")
		e.writeDelta("'s a full ")
		e.writeDelta("breakdown")
		e.endDelta()
	})

	// Chunks appear in the correct order.
	idx := 0
	for _, chunk := range []string{"Here", "'s a full ", "breakdown"} {
		pos := strings.Index(out[idx:], chunk)
		if pos < 0 {
			t.Fatalf("chunk %q missing from output (or out of order)\nfull=%q", chunk, out)
		}
		idx += pos + len(chunk)
	}

	// Between the first and second chunk, we expect exactly one restore
	// (\033[u) to pick up where the previous chunk left off. No \r (CR)
	// should appear there — that was the regression that caused column-1
	// overwrites.
	first := strings.Index(out, "Here")
	second := strings.Index(out, "'s a full ")
	between := out[first+len("Here") : second]
	if !strings.Contains(between, "\x1b[u") {
		t.Fatalf("expected \\033[u between chunks, got %q", between)
	}
	if strings.Contains(between, "\r") {
		t.Fatalf("unexpected CR between chunks — would reset to column 1: between=%q", between)
	}
}

// TestWriteDeltaNonTTYConcatenates verifies the non-TTY fallback path
// preserves text order without using ANSI cursor games.
func TestWriteDeltaNonTTYConcatenates(t *testing.T) {
	e := newLineEditor(&termUI{enabled: false})
	out := captureStderr(t, func() {
		e.writeDelta("a")
		e.writeDelta("bc")
		e.writeDelta("def")
		e.endDelta()
	})
	if !strings.HasPrefix(out, "abcdef") {
		t.Fatalf("expected 'abcdef' prefix, got %q", out)
	}
	if !strings.HasSuffix(strings.TrimRight(out, "\n"), "f") {
		t.Fatalf("expected content to end with 'f' before final newline, got %q", out)
	}
}

// TestWriteOutputClosesActiveStream verifies that if a caller accidentally
// fires an atomic write (tool status, slash command) while a delta stream
// is in flight, writeOutput flushes a newline and clears the streaming
// flag so the two don't collide on the same row.
func TestWriteOutputClosesActiveStream(t *testing.T) {
	ui := &termUI{enabled: true}
	ui.rows.Store(24)
	ui.cols.Store(80)
	e := newLineEditor(ui)

	_ = captureStderr(t, func() {
		e.writeDelta("streaming")
		// No endDelta — simulate a tool event arriving mid-stream.
		e.writeOutput(func() {
			// caller would Fprintf a status line here
		})
	})

	if e.streaming {
		t.Fatalf("writeOutput should clear the streaming flag when it closes an in-flight stream")
	}
}

// --- v0.22.0 readline-style keystrokes ----------------------------------

// TestDeleteWord_RemovesWordBackward locks the Ctrl+W contract,
// matching bash readline `unix-word-rubout`: kill the run of
// non-whitespace before the cursor (consuming any trailing
// whitespace at the cursor first if the cursor sits in a space run).
// Adjacent whitespace BEFORE the killed word is preserved so
// successive Ctrl+W advances by exactly one word per press.
func TestDeleteWord_RemovesWordBackward(t *testing.T) {
	cases := []struct {
		in      string
		cursor  int
		want    string
		wantCur int
	}{
		// Cursor at end of "hello world" → strips "world", keeps " ".
		{"hello world", 11, "hello ", 6},
		// Cursor at end of "hello" alone → strips "hello", buffer empty.
		{"hello", 5, "", 0},
		// Cursor at column 0 — no-op.
		{"abc", 0, "abc", 0},
		// Multiple spaces between words preserved.
		{"foo   bar", 9, "foo   ", 6},
		// Tab counts as whitespace, preserved.
		{"foo\tbar", 7, "foo\t", 4},
		// Cursor in pure-whitespace tail — consumes the spaces AND
		// the preceding word.
		{"hello   ", 8, "", 0},
	}
	for _, c := range cases {
		e := newTestEditor()
		e.buf = []rune(c.in)
		e.cursor = c.cursor
		e.deleteWord()
		if got := string(e.buf); got != c.want {
			t.Errorf("deleteWord(%q@%d): buf = %q, want %q", c.in, c.cursor, got, c.want)
		}
		if e.cursor != c.wantCur {
			t.Errorf("deleteWord(%q@%d): cursor = %d, want %d", c.in, c.cursor, e.cursor, c.wantCur)
		}
	}
}

// TestKillToEnd_ClearsTail locks the Ctrl+K contract: cuts from
// cursor to end of buffer. No-op when already at end.
func TestKillToEnd_ClearsTail(t *testing.T) {
	cases := []struct {
		in     string
		cursor int
		want   string
	}{
		{"hello world", 5, "hello"},
		{"abc", 0, ""},
		{"abc", 3, "abc"}, // already at end → no-op
	}
	for _, c := range cases {
		e := newTestEditor()
		e.buf = []rune(c.in)
		e.cursor = c.cursor
		e.killToEnd()
		if got := string(e.buf); got != c.want {
			t.Errorf("killToEnd(%q@%d): buf = %q, want %q", c.in, c.cursor, got, c.want)
		}
		if e.cursor != c.cursor {
			t.Errorf("killToEnd(%q@%d): cursor moved to %d (should stay)", c.in, c.cursor, e.cursor)
		}
	}
}

// TestHistorySearch_FindsMostRecentSubstring locks the Ctrl+R
// contract: opens search mode, accumulates a substring query, lands
// on the most-recent matching history entry.
func TestHistorySearch_FindsMostRecentSubstring(t *testing.T) {
	e := newTestEditor()
	e.history = []string{
		"audit query --limit 5",
		"wifi scan ap",
		"generate badusb open run dialog",
		"audit export",
		"wifi deauth strongest",
	}

	e.startHistorySearch()
	if !e.searching {
		t.Fatal("startHistorySearch did not enable search mode")
	}

	// Type "audit" — should match the most recent entry containing it
	// ("audit export", index 3).
	for _, r := range "audit" {
		e.runeInSearch(r)
	}
	if e.searchMatch != 3 {
		t.Errorf("searchMatch = %d, want 3 (audit export)", e.searchMatch)
	}
	if string(e.buf) != "audit export" {
		t.Errorf("buf = %q, want audit export", string(e.buf))
	}

	// Cycle older — should land on index 0.
	e.cycleHistorySearchOlder()
	if e.searchMatch != 0 {
		t.Errorf("after cycleOlder: searchMatch = %d, want 0", e.searchMatch)
	}
	if string(e.buf) != "audit query --limit 5" {
		t.Errorf("after cycleOlder: buf = %q", string(e.buf))
	}

	// Accept — search mode off, buffer keeps the matched line.
	e.acceptSearch()
	if e.searching {
		t.Error("acceptSearch should exit search mode")
	}
	if string(e.buf) != "audit query --limit 5" {
		t.Errorf("after accept: buf = %q", string(e.buf))
	}
}

// TestHistorySearch_BackspaceShortensQuery covers the editing path
// — typing too far, deleting characters re-resolves the match.
func TestHistorySearch_BackspaceShortensQuery(t *testing.T) {
	e := newTestEditor()
	e.history = []string{"audit query", "wifi scan"}

	e.startHistorySearch()
	for _, r := range "audix" {
		e.runeInSearch(r)
	}
	if e.searchMatch != -1 {
		t.Errorf("query 'audix': searchMatch = %d, want -1 (no match)", e.searchMatch)
	}
	e.backspaceInSearch() // back to "audi"
	if e.searchMatch != 0 {
		t.Errorf("after backspace: searchMatch = %d, want 0", e.searchMatch)
	}
}

// TestHistorySearch_CancelRestoresBuffer ensures Esc-style cancel
// rolls back to whatever the user was typing before they hit Ctrl+R.
func TestHistorySearch_CancelRestoresBuffer(t *testing.T) {
	e := newTestEditor()
	e.history = []string{"audit query"}
	e.buf = []rune("partial input")
	e.cursor = len(e.buf)

	e.startHistorySearch()
	for _, r := range "audit" {
		e.runeInSearch(r)
	}
	if string(e.buf) != "audit query" {
		t.Fatalf("after match: buf = %q", string(e.buf))
	}

	e.cancelSearch()
	if e.searching {
		t.Error("cancelSearch should exit search mode")
	}
	if string(e.buf) != "partial input" {
		t.Errorf("after cancel: buf = %q, want partial input", string(e.buf))
	}
}

// TestSearchPrompt_RendersStatus covers the prompt-prefix renderer
// the REPL uses when search mode is active. Failed-match state has
// a distinct prefix so the operator sees the search isn't landing.
func TestSearchPrompt_RendersStatus(t *testing.T) {
	e := newTestEditor()
	e.history = []string{"audit query"}
	if e.SearchPrompt() != "" {
		t.Error("SearchPrompt should be empty when not searching")
	}
	e.startHistorySearch()
	for _, r := range "audit" {
		e.runeInSearch(r)
	}
	if got := e.SearchPrompt(); got != "(reverse-i-search)`audit': " {
		t.Errorf("SearchPrompt = %q", got)
	}
	for _, r := range "xx" {
		e.runeInSearch(r)
	}
	if got := e.SearchPrompt(); got != "(failed reverse-i-search)`auditxx': " {
		t.Errorf("failed-prompt = %q", got)
	}
}
