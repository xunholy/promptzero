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
