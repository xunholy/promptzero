package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRunShutdownHooks_NormalAndPanic exercises the panic-recovery
// guard added to runShutdownHooks: a hook that panics must not
// propagate the panic up through the goroutine and must not block
// subsequent hooks from firing. Pin the contract so a future
// refactor that drops the recover() reintroduces silent crashes.
func TestRunShutdownHooks_NormalAndPanic(t *testing.T) {
	var ranBefore atomic.Bool
	var ranAfter atomic.Bool
	var sh signalHandler
	sh.AddShutdownHook(func() { ranBefore.Store(true) })
	sh.AddShutdownHook(func() { panic("hook-panic-marker") })
	sh.AddShutdownHook(func() { ranAfter.Store(true) })

	// runShutdownHooks runs each hook in its own goroutine with a 2 s
	// per-hook timeout. We need to wait long enough for the goroutines
	// to flush — the helper itself doesn't await final completion.
	sh.runShutdownHooks()
	// Settle: the hooks set bools synchronously inside the goroutine,
	// but the goroutine launch + select adds nanos of slop. A short
	// poll-loop avoids both flakiness and a hardcoded sleep.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if ranBefore.Load() && ranAfter.Load() {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !ranBefore.Load() {
		t.Error("first hook (before panic) did not run")
	}
	if !ranAfter.Load() {
		t.Error("third hook (after panic) did not run — recover did not contain the panic")
	}
}

// TestRunShutdownHooks_TimeoutDoesNotWedge ensures that a hook that
// hangs forever doesn't block process shutdown. The runShutdownHooks
// helper uses a 2-second per-hook timeout; we set a hook that
// blocks indefinitely on a channel and confirm runShutdownHooks
// returns within a tight wall-clock budget.
func TestRunShutdownHooks_TimeoutDoesNotWedge(t *testing.T) {
	if testing.Short() {
		t.Skip("slow; exercises the 2s shutdown-hook timeout")
	}
	stuck := make(chan struct{}) // never closed → hook blocks forever
	defer close(stuck)
	var sh signalHandler
	sh.AddShutdownHook(func() { <-stuck })
	var wg sync.WaitGroup
	wg.Add(1)
	start := time.Now()
	go func() {
		defer wg.Done()
		sh.runShutdownHooks()
	}()
	wg.Wait()
	elapsed := time.Since(start)
	// 2 s per-hook timeout plus a small generous margin.
	if elapsed > 3*time.Second {
		t.Errorf("runShutdownHooks did not respect the per-hook timeout (took %v)", elapsed)
	}
}
