// Package watch implements the --watch filesystem-trigger mode.
//
// A Watcher observes one or more directories via fsnotify, matches new /
// modified files against a set of rules (glob pattern -> prompt template),
// and hands the result to a caller-supplied handler. Rapid write bursts
// against the same path are debounced so an atomic save sequence
// (truncate + rewrite + rename) doesn't dispatch the handler three times.
//
// The Watcher is intentionally agnostic of the agent loop — callers plug
// the handler into whatever dispatch mechanism they prefer. promptzero
// wires it to ai.Run so FS events become natural-language turns.
package watch

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Rule is a single pattern -> prompt mapping with an optional persona
// override. Pattern uses filepath.Match semantics against the file basename.
// Prompt is templated with {{path}}, {{dir}}, {{name}}, {{ext}} when the
// handler fires.
type Rule struct {
	Pattern string
	Prompt  string
	Persona string
}

// Handler is the callback invoked when a file matches a rule. Returning an
// error is non-fatal; the Watcher logs and continues processing events.
type Handler func(rule Rule, path string) error

// Event is a record of one dispatched rule firing. Kept in-memory on the
// Watcher for the /watch slash command's "last 5 events" view.
type Event struct {
	At    time.Time
	Path  string
	Rule  Rule
	Error error
}

// Watcher debounces and dispatches fsnotify events through the configured
// rule set. Zero value is not usable — construct via New.
type Watcher struct {
	paths    []string
	rules    []Rule
	debounce time.Duration

	mu      sync.Mutex
	paused  atomic.Bool
	history []Event
	pending map[string]*time.Timer
}

// debounceWindow collapses writes to the same path inside this interval
// into a single handler firing. Long enough to cover a "write -> rename"
// atomic save; short enough that the user doesn't feel latency.
const debounceWindow = 500 * time.Millisecond

// eventHistory caps how many past events we keep around for /watch.
// Bounded so a long-running session doesn't leak memory via the ring.
const eventHistory = 32

// New constructs a Watcher from a list of paths and rules. The slices are
// copied so the caller can mutate the originals without racing the watcher.
func New(paths []string, rules []Rule) *Watcher {
	ps := append([]string(nil), paths...)
	rs := append([]Rule(nil), rules...)
	return &Watcher{
		paths:    ps,
		rules:    rs,
		debounce: debounceWindow,
		pending:  map[string]*time.Timer{},
	}
}

// Paths returns the list of watched paths. Copy — callers must not mutate.
func (w *Watcher) Paths() []string {
	out := make([]string, len(w.paths))
	copy(out, w.paths)
	return out
}

// Rules returns the configured rule set. Copy — callers must not mutate.
func (w *Watcher) Rules() []Rule {
	out := make([]Rule, len(w.rules))
	copy(out, w.rules)
	return out
}

// Pause silences the watcher without stopping it; queued and subsequent
// events are still observed but handlers are not invoked until Resume.
func (w *Watcher) Pause() { w.paused.Store(true) }

// Resume re-enables dispatch after a Pause.
func (w *Watcher) Resume() { w.paused.Store(false) }

// Paused reports whether dispatch is currently suppressed.
func (w *Watcher) Paused() bool { return w.paused.Load() }

// Recent returns up to n most-recent events, newest first. Pass a small
// number (5-20) — history is bounded by eventHistory anyway.
func (w *Watcher) Recent(n int) []Event {
	w.mu.Lock()
	defer w.mu.Unlock()
	if n > len(w.history) {
		n = len(w.history)
	}
	out := make([]Event, n)
	for i := 0; i < n; i++ {
		out[i] = w.history[len(w.history)-1-i]
	}
	return out
}

// Run blocks until ctx is cancelled, dispatching matching events to
// handler. Errors opening the underlying fsnotify watcher are returned
// immediately; runtime errors are logged and the loop continues.
func (w *Watcher) Run(ctx context.Context, handler Handler) error {
	if handler == nil {
		return errors.New("watch: handler is nil")
	}
	if len(w.paths) == 0 {
		return nil
	}
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watch: new fsnotify: %w", err)
	}
	defer fw.Close()

	for _, p := range w.paths {
		if err := fw.Add(p); err != nil {
			return fmt.Errorf("watch: add %s: %w", p, err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			w.flushTimers()
			return nil
		case ev, ok := <-fw.Events:
			if !ok {
				return nil
			}
			if ev.Op&(fsnotify.Create|fsnotify.Write) == 0 {
				continue
			}
			if ignore(ev.Name) {
				continue
			}
			w.scheduleDispatch(ev.Name, handler)
		case err, ok := <-fw.Errors:
			if !ok {
				return nil
			}
			log.Printf("watch: fsnotify error: %v", err)
		}
	}
}

// scheduleDispatch debounces repeated events for the same path. The timer
// resets on each event; only after debounceWindow of silence does the
// handler actually fire. The rule match is re-evaluated at fire time so a
// rename in the middle of the save sequence still gets classified
// correctly.
func (w *Watcher) scheduleDispatch(path string, handler Handler) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.pending[path]; ok {
		t.Stop()
	}
	w.pending[path] = time.AfterFunc(w.debounce, func() {
		w.mu.Lock()
		delete(w.pending, path)
		w.mu.Unlock()
		w.dispatch(path, handler)
	})
}

// flushTimers cancels any in-flight debounced deliveries. Called on ctx
// cancellation so pending timers don't fire after shutdown.
func (w *Watcher) flushTimers() {
	w.mu.Lock()
	defer w.mu.Unlock()
	for k, t := range w.pending {
		t.Stop()
		delete(w.pending, k)
	}
}

func (w *Watcher) dispatch(path string, handler Handler) {
	if w.paused.Load() {
		return
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return
	}
	rule, ok := w.match(path)
	if !ok {
		return
	}
	prompt := substitute(rule.Prompt, path)
	err = handler(Rule{Pattern: rule.Pattern, Prompt: prompt, Persona: rule.Persona}, path)
	w.recordEvent(Event{At: time.Now(), Path: path, Rule: rule, Error: err})
	if err != nil {
		log.Printf("watch: handler for %s: %v", path, err)
	}
}

func (w *Watcher) recordEvent(e Event) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.history = append(w.history, e)
	if len(w.history) > eventHistory {
		w.history = w.history[len(w.history)-eventHistory:]
	}
}

func (w *Watcher) match(path string) (Rule, bool) {
	base := filepath.Base(path)
	for _, r := range w.rules {
		ok, err := filepath.Match(r.Pattern, base)
		if err == nil && ok {
			return r, true
		}
	}
	return Rule{}, false
}

// substitute replaces {{path}}, {{dir}}, {{name}}, {{ext}} placeholders
// inside tmpl with values derived from path. Unknown placeholders are
// left alone — the agent will see them verbatim, which makes typos
// obvious rather than silently swallowed.
func substitute(tmpl, path string) string {
	dir, file := filepath.Split(path)
	ext := filepath.Ext(file)
	name := strings.TrimSuffix(file, ext)
	r := strings.NewReplacer(
		"{{path}}", path,
		"{{dir}}", strings.TrimRight(dir, string(filepath.Separator)),
		"{{name}}", name,
		"{{ext}}", ext,
	)
	return r.Replace(tmpl)
}

// ignore filters out dotfiles, editor swap/backup files, and anything
// under a .git/ directory. Keeps the agent from reacting to noise that
// humans also ignore.
func ignore(path string) bool {
	base := filepath.Base(path)
	if strings.HasPrefix(base, ".") {
		return true
	}
	if strings.HasSuffix(base, "~") || strings.HasSuffix(base, ".swp") || strings.HasSuffix(base, ".swx") {
		return true
	}
	if strings.Contains(path, string(filepath.Separator)+".git"+string(filepath.Separator)) {
		return true
	}
	return false
}
