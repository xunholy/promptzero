package web

import (
	"context"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/agent"
)

// TestStart_BindErrorDoesNotLeakShutdownGoroutine guards the shutdown-goroutine
// lifecycle on the failed-bind path. Start spawns a goroutine that blocks on
// the context until shutdown; if ListenAndServe returns a non-ErrServerClosed
// error (a bind failure — the port is already in use), Start returns the error
// but, pre-fix, never cancels that context, so the goroutine blocks on
// <-ctx.Done() forever — a leak on every failed bind. The fix derives a
// cancellable context with a deferred cancel so the goroutine is reaped on
// every return path.
//
// Detection mirrors internal/agent/streaming_test.go: compare
// runtime.NumGoroutine before and after; pre-fix the count stays elevated,
// post-fix it returns to baseline. The caller's ctx is deliberately left
// uncancelled until test teardown so only Start's own cleanup can reap the
// goroutine.
func TestStart_BindErrorDoesNotLeakShutdownGoroutine(t *testing.T) {
	// Occupy a loopback port so Start's ListenAndServe fails to bind.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer ln.Close()

	s := &Server{
		agent:             &fakeAgent{},
		addr:              ln.Addr().String(),
		conns:             make(map[*sessionConn]struct{}),
		confirms:          make(map[string]chan agent.ConfirmResponse),
		heartbeatInterval: 100 * time.Millisecond,
		heartbeatTimeout:  2 * time.Second,
		writeTimeout:      2 * time.Second,
		startedAt:         time.Now(),
	}
	s.attachAgentCallbacks()

	// Settle so goroutines from earlier tests have exited before the snapshot.
	runtime.Gosched()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // left uncancelled during the assertion below

	if err := s.Start(ctx); err == nil {
		t.Fatal("expected a bind error from Start on an already-occupied port, got nil")
	}

	// Poll for goroutine cleanup. Pre-fix the shutdown goroutine is stuck on
	// <-ctx.Done() (ctx still live), so the count stays above baseline;
	// post-fix Start's deferred cancel reaps it.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("shutdown goroutine leaked: %d goroutines before Start, %d still alive 2s after its bind error returned",
		before, runtime.NumGoroutine())
}
