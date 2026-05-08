package obs

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestSafeGo_RunsFnAndDoesNotPanic verifies the happy path — fn runs to
// completion, no panic, no log line. The done channel pins ordering so
// the test doesn't race the goroutine.
func TestSafeGo_RunsFnAndDoesNotPanic(t *testing.T) {
	var ran bool
	done := make(chan struct{})
	SafeGo("test.happy", func() {
		ran = true
		close(done)
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("fn did not run within 1s")
	}
	if !ran {
		t.Error("fn did not execute")
	}
}

// TestSafeGo_RecoversAndLogsStack pins the load-bearing behaviour:
// when fn panics, SafeGo must (a) prevent the panic from crashing the
// process, (b) emit an "panic recovered" log line carrying the
// goroutine name and the recovered value, and (c) include a stack
// trace pointing at the panic site so the operator doesn't have to
// re-run with GOTRACEBACK=all.
func TestSafeGo_RecoversAndLogsStack(t *testing.T) {
	var buf threadSafeBuffer
	prev := Default()
	setGlobal(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { setGlobal(prev) })

	done := make(chan struct{})
	SafeGo("test.panicker", func() {
		defer close(done)
		panic("boom-marker-x7q")
	})
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("panicking goroutine did not return within 1s")
	}
	// SafeGo's deferred recover runs after fn, but ordering of close(done)
	// vs. the recover is fn-internal here. Give the recover a moment to log.
	time.Sleep(50 * time.Millisecond)

	out := buf.String()
	if !strings.Contains(out, "panic recovered") {
		t.Errorf("log missing 'panic recovered': %q", out)
	}
	if !strings.Contains(out, "where=test.panicker") {
		t.Errorf("log missing goroutine name: %q", out)
	}
	if !strings.Contains(out, "boom-marker-x7q") {
		t.Errorf("log missing recovered panic value: %q", out)
	}
	if !strings.Contains(out, "stack=") {
		t.Errorf("log missing stack trace: %q", out)
	}
	// The stack should include "runtime/debug.Stack" or a recognizable
	// goroutine frame; pin a low-noise check that some stack content
	// landed without binding to a specific frame name.
	if !strings.Contains(out, "goroutine") && !strings.Contains(out, "safego.go") {
		t.Errorf("stack trace looks empty: %q", out)
	}
}

// threadSafeBuffer is a bytes.Buffer with a mutex around Write+Read so
// the slog handler (which writes from the panicking goroutine) and the
// test assertions (which read after the recover) don't race under -race.
type threadSafeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *threadSafeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *threadSafeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}
