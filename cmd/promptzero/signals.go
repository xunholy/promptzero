package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"time"
)

// signalHandler owns the atomic pointers the Ctrl+C goroutine needs: the
// in-flight cancel, the last SIGINT timestamp (for the 2s double-tap),
// the active termUI (to tear it down on a hard exit), and the raw-mode
// restore fn (so the terminal gets reset before os.Exit).
//
// A first Ctrl+C cancels the in-flight op; a second within doubleTapWindow
// restores the terminal, tears the UI down, and exits. This matches the
// Claude Code / modern-CLI feel.
type signalHandler struct {
	currentCancel atomic.Pointer[context.CancelFunc]
	lastSIGINT    atomic.Int64
	uiRef         atomic.Pointer[termUI]
	stdinRestore  atomic.Pointer[func()]
}

const signalDoubleTapWindow = 2 * time.Second

// install registers the SIGINT handler goroutine and returns a cleanup
// fn that stops signal delivery. Caller should `defer sh.install()()`.
func (s *signalHandler) install() func() {
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt)
	go s.run(sigCh)
	return func() { signal.Stop(sigCh) }
}

// run drains SIGINTs until the channel closes, implementing the
// cancel-once / exit-on-second-tap behaviour.
func (s *signalHandler) run(sigCh <-chan os.Signal) {
	for range sigCh {
		now := time.Now().UnixNano()
		prev := s.lastSIGINT.Swap(now)
		within := prev != 0 && time.Duration(now-prev) < signalDoubleTapWindow

		if within {
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
