package watch

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatcherFiresOnceWithSubstitutedPrompt(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; rerun without -short")
	}
	dir := t.TempDir()
	w := New([]string{dir}, []Rule{{
		Pattern: "*.sub",
		Prompt:  "Decode {{path}} — ext={{ext}} name={{name}} dir={{dir}}",
	}})

	var (
		mu    sync.Mutex
		rules []Rule
		paths []string
	)
	handler := func(r Rule, p string) error {
		mu.Lock()
		defer mu.Unlock()
		rules = append(rules, r)
		paths = append(paths, p)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- w.Run(ctx, handler) }()

	// Give fsnotify a moment to settle so the Add() above is active before
	// we drop a file into the watched dir — avoids a race where the test
	// file is created before fsnotify starts delivering events.
	time.Sleep(100 * time.Millisecond)

	target := filepath.Join(dir, "capture.sub")
	if err := os.WriteFile(target, []byte("hello"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Wait past the debounce window plus a small cushion, then cancel.
	// 500ms debounce + 400ms cushion = 900ms.
	time.Sleep(900 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 1 {
		t.Fatalf("expected 1 handler call, got %d (paths=%v)", len(paths), paths)
	}
	if paths[0] != target {
		t.Errorf("path = %q, want %q", paths[0], target)
	}
	want := []string{
		"Decode " + target,
		"ext=.sub",
		"name=capture",
	}
	for _, s := range want {
		if !strings.Contains(rules[0].Prompt, s) {
			t.Errorf("prompt missing %q: %s", s, rules[0].Prompt)
		}
	}
}

func TestWatcherDebouncesBurstWrites(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; rerun without -short")
	}
	dir := t.TempDir()
	w := New([]string{dir}, []Rule{{Pattern: "*.png", Prompt: "{{path}}"}})
	var calls atomic.Int32
	handler := func(_ Rule, _ string) error {
		calls.Add(1)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go w.Run(ctx, handler)
	time.Sleep(100 * time.Millisecond)

	target := filepath.Join(dir, "a.png")
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(target, []byte{byte(i)}, 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(900 * time.Millisecond)
	cancel()

	if got := calls.Load(); got != 1 {
		t.Errorf("expected 1 debounced call, got %d", got)
	}
}

func TestWatcherIgnoresDotfilesAndSwap(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; rerun without -short")
	}
	dir := t.TempDir()
	w := New([]string{dir}, []Rule{{Pattern: "*", Prompt: "{{path}}"}})
	var calls atomic.Int32
	handler := func(_ Rule, _ string) error {
		calls.Add(1)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go w.Run(ctx, handler)
	time.Sleep(100 * time.Millisecond)

	for _, name := range []string{".hidden", "note.swp", "note~"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	time.Sleep(800 * time.Millisecond)
	cancel()

	if got := calls.Load(); got != 0 {
		t.Errorf("ignored files should not dispatch, got %d calls", got)
	}
}

func TestWatcherPauseSuppressesDispatch(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; rerun without -short")
	}
	dir := t.TempDir()
	w := New([]string{dir}, []Rule{{Pattern: "*.sub", Prompt: "{{path}}"}})
	w.Pause()
	var calls atomic.Int32
	handler := func(_ Rule, _ string) error {
		calls.Add(1)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go w.Run(ctx, handler)
	time.Sleep(100 * time.Millisecond)

	if err := os.WriteFile(filepath.Join(dir, "x.sub"), []byte("y"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(800 * time.Millisecond)
	cancel()
	if got := calls.Load(); got != 0 {
		t.Errorf("paused watcher dispatched: %d calls", got)
	}
}

func TestSubstitute(t *testing.T) {
	p := "/tmp/flipper/capture.sub"
	got := substitute("path={{path}} dir={{dir}} name={{name}} ext={{ext}}", p)
	want := "path=/tmp/flipper/capture.sub dir=/tmp/flipper name=capture ext=.sub"
	if got != want {
		t.Errorf("substitute: %q, want %q", got, want)
	}
}

// TestValidatePattern locks the config-load-time pattern check.
// Without this, malformed patterns silently never matched at runtime
// (filepath.Match returns ErrBadPattern; the watcher's matcher
// swallowed the error and treated it as no-match). Operators saw
// "watcher running" and "no events fired" with no signal that their
// pattern was the problem.
func TestValidatePattern(t *testing.T) {
	t.Run("accepts_well_formed", func(t *testing.T) {
		for _, p := range []string{
			"*.sub", "*.png", "capture.*", "[abc]*.txt", "[a-z]?.bin",
			"file?.dat", "exact.txt",
		} {
			if err := ValidatePattern(p); err != nil {
				t.Errorf("%q should validate: %v", p, err)
			}
		}
	})
	t.Run("rejects_malformed", func(t *testing.T) {
		// Unmatched bracket and trailing backslash are the canonical
		// ErrBadPattern triggers documented in the stdlib.
		for _, p := range []string{"*[a.sub", "[", "foo[bar", "trail\\"} {
			if err := ValidatePattern(p); err == nil {
				t.Errorf("%q should error", p)
			}
		}
	})
}

// TestIgnore_TemplatesAndCase locks the v0.24.x ignore-rule expansions:
// case-insensitive suffix matching (.SWP / .Bak no longer slip past
// the lowercase hardcoded list), additional editor temp/backup
// patterns (.swo, .bak, .tmp), browser-download partials
// (.crdownload, .part, .partial), and Windows OS noise files
// (Thumbs.db, desktop.ini).
func TestIgnore_TemplatesAndCase(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// existing rules — confirm regression-free
		{"/tmp/x/.hidden", true},
		{"/tmp/x/notes.swp", true},
		{"/tmp/x/notes~", true},
		{"/tmp/x/repo/.git/HEAD", true},
		// case-insensitive suffix variants
		{"/tmp/x/notes.SWP", true},
		{"/tmp/x/notes.Swo", true},
		// new generic backup/temp suffixes
		{"/tmp/x/draft.bak", true},
		{"/tmp/x/draft.BAK", true},
		{"/tmp/x/draft.tmp", true},
		// browser partials
		{"/tmp/x/file.crdownload", true},
		{"/tmp/x/file.part", true},
		{"/tmp/x/file.partial", true},
		// Windows noise
		{"/tmp/x/Thumbs.db", true},
		{"/tmp/x/desktop.ini", true},
		// regular files should NOT be ignored
		{"/tmp/x/capture.sub", false},
		{"/tmp/x/notes.txt", false},
	}
	for _, tc := range cases {
		if got := ignore(tc.path); got != tc.want {
			t.Errorf("ignore(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestMatch_CaseInsensitive locks the case-insensitive match contract.
// Browsers, screenshot tools, and some CFW SD-card writers emit mixed-
// case extensions (.PNG, .SUB, .NFC). The watcher pattern *.sub should
// catch them all without operators having to enumerate every case
// variant in their config.
func TestMatch_CaseInsensitive(t *testing.T) {
	w := New([]string{"/tmp/x"}, []Rule{
		{Pattern: "*.sub", Prompt: "decode {{path}}"},
		{Pattern: "*.PNG", Prompt: "ocr {{path}}"},
	})
	cases := []struct {
		path     string
		want     bool
		wantRule string
	}{
		{"/tmp/x/capture.sub", true, "*.sub"},
		{"/tmp/x/capture.SUB", true, "*.sub"},
		{"/tmp/x/Capture.SuB", true, "*.sub"},
		{"/tmp/x/screenshot.png", true, "*.PNG"},
		{"/tmp/x/screenshot.PNG", true, "*.PNG"},
		{"/tmp/x/file.txt", false, ""},
	}
	for _, tc := range cases {
		got, ok := w.match(tc.path)
		if ok != tc.want {
			t.Errorf("match(%q) ok = %v, want %v", tc.path, ok, tc.want)
			continue
		}
		if tc.want && got.Pattern != tc.wantRule {
			t.Errorf("match(%q) Pattern = %q, want %q", tc.path, got.Pattern, tc.wantRule)
		}
	}
}

// TestPathsAndRulesReturnCopies pins the immutability contract on
// the two accessors: callers can mutate the returned slice without
// corrupting the watcher's internal state. The /watch slash command
// renders these to operators; if it could mutate them inadvertently
// the watcher's matching behaviour would drift mid-session.
func TestPathsAndRulesReturnCopies(t *testing.T) {
	origPaths := []string{"/path/a", "/path/b"}
	origRules := []Rule{
		{Pattern: "*.sub", Prompt: "decode {{path}}", Persona: "rf"},
		{Pattern: "*.nfc", Prompt: "read {{path}}"},
	}
	w := New(origPaths, origRules)

	gotPaths := w.Paths()
	if len(gotPaths) != 2 || gotPaths[0] != "/path/a" || gotPaths[1] != "/path/b" {
		t.Errorf("Paths() = %v, want [/path/a /path/b]", gotPaths)
	}
	gotPaths[0] = "/CORRUPTED"
	if again := w.Paths(); again[0] != "/path/a" {
		t.Errorf("Paths() returns shared slice — mutation leaked: %v", again)
	}

	gotRules := w.Rules()
	if len(gotRules) != 2 || gotRules[0].Pattern != "*.sub" || gotRules[1].Pattern != "*.nfc" {
		t.Errorf("Rules() = %+v, want 2 rules", gotRules)
	}
	gotRules[0].Pattern = "CORRUPTED"
	if again := w.Rules(); again[0].Pattern != "*.sub" {
		t.Errorf("Rules() returns shared slice — mutation leaked: %+v", again)
	}

	// Input-slice mutation must not affect the watcher (New copies).
	origPaths[0] = "/MUTATED"
	if again := w.Paths(); again[0] != "/path/a" {
		t.Errorf("input mutation leaked into watcher: Paths()[0] = %q", again[0])
	}
}

// TestPauseResumePausedRoundTrip pins the /watch pause/resume state
// machine the operator UX toggles.
func TestPauseResumePausedRoundTrip(t *testing.T) {
	w := New(nil, nil)

	if w.Paused() {
		t.Errorf("freshly-constructed watcher reports Paused=true, want false")
	}
	w.Pause()
	if !w.Paused() {
		t.Errorf("after Pause(), Paused() = false")
	}
	w.Pause() // idempotent
	if !w.Paused() {
		t.Errorf("double-Pause() should stay paused")
	}
	w.Resume()
	if w.Paused() {
		t.Errorf("after Resume(), Paused() = true")
	}
	w.Resume() // idempotent
	if w.Paused() {
		t.Errorf("double-Resume() should stay running")
	}
}

// TestRecentReturnsNewestFirst pins the /watch slash command's
// recent-events render order: newest first, capped at n and at
// len(history).
func TestRecentReturnsNewestFirst(t *testing.T) {
	w := New(nil, nil)

	now := time.Now()
	w.history = []Event{
		{At: now, Path: "/a"},
		{At: now.Add(time.Second), Path: "/b"},
		{At: now.Add(2 * time.Second), Path: "/c"},
		{At: now.Add(3 * time.Second), Path: "/d"},
	}

	got := w.Recent(2)
	if len(got) != 2 {
		t.Fatalf("Recent(2) returned %d events, want 2", len(got))
	}
	if got[0].Path != "/d" {
		t.Errorf("Recent(2)[0].Path = %q, want /d (newest)", got[0].Path)
	}
	if got[1].Path != "/c" {
		t.Errorf("Recent(2)[1].Path = %q, want /c", got[1].Path)
	}

	all := w.Recent(10)
	if len(all) != 4 {
		t.Errorf("Recent(10) returned %d events, want 4 (capped at len(history))", len(all))
	}
	if all[0].Path != "/d" || all[3].Path != "/a" {
		t.Errorf("Recent(10) wrong order: %v", all)
	}

	empty := w.Recent(0)
	if len(empty) != 0 {
		t.Errorf("Recent(0) returned %d events, want 0", len(empty))
	}

	w.history = nil
	if got := w.Recent(5); len(got) != 0 {
		t.Errorf("Recent on empty history returned %d events, want 0", len(got))
	}
}

// TestScheduleDispatch_RecoversPanickingHandler pins the v0.94 fix.
// time.AfterFunc runs its callback in its own goroutine; without a
// recover wrapper a panicking host handler crashes the agent
// process (the outer fsnotify Run loop's obs.SafeGo doesn't reach
// the debounced timer goroutine). Mirrors the recover pattern
// agent.safeCallToolStream and agent.safeCallToolStatus apply on
// the other host-callback paths.
//
// The test calls scheduleDispatch directly with a panicking
// handler, waits for the debounce window to fire, and verifies
// the process is still alive. Pre-fix the time.AfterFunc goroutine
// would panic without recovery and the test runner would crash.
func TestScheduleDispatch_RecoversPanickingHandler(t *testing.T) {
	dir := t.TempDir()
	tmpFile := filepath.Join(dir, "x.sub")
	if err := os.WriteFile(tmpFile, []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	w := New([]string{dir}, []Rule{{
		Pattern: "*.sub",
		Prompt:  "decode {{path}}",
	}})
	// Tight debounce so the test doesn't wait long.
	w.debounce = 10 * time.Millisecond

	handler := func(_ Rule, _ string) error {
		panic("simulated host handler crash")
	}

	w.scheduleDispatch(tmpFile, handler)

	// Wait long enough for the debounce timer to fire + recover to
	// run. If the panic escapes the goroutine the test binary
	// crashes before this returns.
	time.Sleep(100 * time.Millisecond)

	// Sanity: the pending map entry should be gone (dispatch ran
	// far enough to remove it before the panic).
	w.mu.Lock()
	_, stillPending := w.pending[tmpFile]
	w.mu.Unlock()
	if stillPending {
		t.Errorf("scheduleDispatch entry still pending after timer fired — debounce path didn't run")
	}
}
