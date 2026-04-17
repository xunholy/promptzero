package main

import (
	"testing"
)

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
