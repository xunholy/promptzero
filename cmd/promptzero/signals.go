package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/xunholy/promptzero/internal/obs"
)

// signalHandler owns the atomic pointers the Ctrl+C goroutine needs: the
// in-flight cancel, the last SIGINT timestamp (for the 2s double-tap),
// the active termUI (to tear it down on a hard exit), and the raw-mode
// restore fn (so the terminal gets reset before os.Exit).
//
// A first Ctrl+C cancels the in-flight op; a second within doubleTapWindow
// restores the terminal, tears the UI down, and exits. This matches the
// Claude Code / modern-CLI feel.
//
// SIGHUP and SIGTERM (added in v0.21.0 per the SRE review) take the
// hard-exit path immediately — no double-tap. They're the canonical
// "you're done" signals from a terminal hangup or a kill -TERM, and
// rolling out the orphaned-tool_use cleanup before the process dies
// is the operator-friendly behaviour.
type signalHandler struct {
	currentCancel atomic.Pointer[context.CancelFunc]
	lastSIGINT    atomic.Int64
	uiRef         atomic.Pointer[termUI]
	stdinRestore  atomic.Pointer[func()]
	// shutdownHooks are run in registration order on SIGHUP/SIGTERM
	// or on the second SIGINT. Used by setup.go to wire Marauder
	// stop-attack calls and audit-log close so the process exits
	// without leaving the Marauder firmware mid-attack or the audit
	// DB open.
	shutdownHooksMu atomic.Pointer[shutdownHookList]
}

// shutdownHookList is an immutable slice we swap atomically when
// hooks register. Avoids a sync.Mutex on the hot signal path.
type shutdownHookList struct{ hooks []func() }

const signalDoubleTapWindow = 2 * time.Second

// install registers the SIGINT / SIGHUP / SIGTERM handler goroutine
// and returns a cleanup fn that stops signal delivery. Caller should
// `defer sh.install()()`.
func (s *signalHandler) install() func() {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	go s.run(sigCh)
	return func() { signal.Stop(sigCh) }
}

// AddShutdownHook registers a function to run on hard-exit
// (SIGHUP/SIGTERM/double-Ctrl-C). Hooks fire in registration order
// before the terminal is restored and the process exits.
func (s *signalHandler) AddShutdownHook(fn func()) {
	for {
		cur := s.shutdownHooksMu.Load()
		var next *shutdownHookList
		if cur == nil {
			next = &shutdownHookList{hooks: []func(){fn}}
		} else {
			h := make([]func(), len(cur.hooks)+1)
			copy(h, cur.hooks)
			h[len(cur.hooks)] = fn
			next = &shutdownHookList{hooks: h}
		}
		if s.shutdownHooksMu.CompareAndSwap(cur, next) {
			return
		}
	}
}

// runShutdownHooks executes every registered hook with a brief
// per-hook timeout so a misbehaving hook can't wedge process exit.
// Errors from hooks are intentionally swallowed — we're shutting
// down anyway and have no good place to surface them.
func (s *signalHandler) runShutdownHooks() {
	cur := s.shutdownHooksMu.Load()
	if cur == nil {
		return
	}
	for _, fn := range cur.hooks {
		done := make(chan struct{})
		go func(f func()) {
			defer close(done)
			defer func() {
				if r := recover(); r != nil {
					// Surface the panic via obs so a buggy shutdown
					// hook is visible in the operator's log even
					// though we proceed with shutdown anyway.
					obs.Default().Error("shutdown_hook_panicked",
						"recovered", fmt.Sprintf("%v", r),
						"stack", string(debug.Stack()))
				}
			}()
			f()
		}(fn)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			// Hook took too long — move on. Anything that needs
			// more than 2s during shutdown is broken.
		}
	}
}

// run drains signals until the channel closes. SIGINT implements the
// cancel-once / exit-on-second-tap behaviour; SIGHUP/SIGTERM take the
// immediate hard-exit path with shutdown hooks.
func (s *signalHandler) run(sigCh <-chan os.Signal) {
	for sig := range sigCh {
		// SIGHUP (terminal hangup) and SIGTERM (kill / process
		// supervisor) → immediate clean shutdown. No double-tap.
		if sig == syscall.SIGHUP || sig == syscall.SIGTERM {
			if cfp := s.currentCancel.Load(); cfp != nil {
				(*cfp)()
			}
			s.runShutdownHooks()
			if fn := s.stdinRestore.Load(); fn != nil {
				(*fn)()
			}
			if u := s.uiRef.Load(); u != nil {
				u.teardown()
			}
			fmt.Fprintf(os.Stderr, "\n  %sShutdown (%s).%s\n\n", dim, sig, reset)
			os.Exit(0)
		}

		// SIGINT path — cancel-once, exit-on-second-tap.
		now := time.Now().UnixNano()
		prev := s.lastSIGINT.Swap(now)
		within := prev != 0 && time.Duration(now-prev) < signalDoubleTapWindow

		if within {
			s.runShutdownHooks()
			if fn := s.stdinRestore.Load(); fn != nil {
				(*fn)()
			}
			if u := s.uiRef.Load(); u != nil {
				u.teardown()
			}
			fmt.Fprintf(os.Stderr, "\n  %sGoodbye.%s\n\n", dim, reset)
			os.Exit(0)
		}
		if cfp := s.currentCancel.Load(); cfp != nil {
			(*cfp)()
		}
		if u := s.uiRef.Load(); u != nil {
			u.positionOutput()
		}
		fmt.Fprintf(os.Stderr, "\n  %s(Ctrl+C again within 2s to exit)%s\n", dim, reset)
		if u := s.uiRef.Load(); u != nil {
			u.drawInputLineEmpty()
			u.positionInput()
		}
	}
}

// withCancel wraps parent with a cancellable context and registers it as
// the "current" operation, so the next SIGINT (or keyboard Ctrl+C) will
// cancel it. The returned release fn both unregisters the pointer and
// cancels the context — callers defer it.
func (s *signalHandler) withCancel(parent context.Context) (context.Context, func()) {
	opCtx, cancel := context.WithCancel(parent)
	cf := context.CancelFunc(cancel)
	s.currentCancel.Store(&cf)
	return opCtx, func() {
		s.currentCancel.Store(nil)
		cancel()
	}
}

// cancelCurrent fires the currently registered cancel, if any. Used by
// the REPL's in-band Ctrl+C keystroke handler (the signal goroutine
// handles the signal path).
func (s *signalHandler) cancelCurrent() {
	if cfp := s.currentCancel.Load(); cfp != nil {
		(*cfp)()
	}
}

// setUI publishes the active termUI so the signal handler can reposition
// the cursor and redraw the input line after a cancel.
func (s *signalHandler) setUI(ui *termUI) { s.uiRef.Store(ui) }

// setStdinRestore publishes the raw-mode restore closure so a hard exit
// can undo termios before os.Exit leaves the shell in a broken state.
func (s *signalHandler) setStdinRestore(fn *func()) { s.stdinRestore.Store(fn) }
