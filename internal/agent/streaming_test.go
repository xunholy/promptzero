package agent

import (
	"context"
	"encoding/json"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/streaming"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

// TestSetToolStreamCallback_RoundTrip pins the public attach/detach
// surface. Nil clears the callback (which falls dispatch back to
// the non-streaming path).
func TestSetToolStreamCallback_RoundTrip(t *testing.T) {
	a := &Agent{}
	if a.toolStreamCb != nil {
		t.Errorf("zero-value Agent should not have a stream callback")
	}
	called := false
	a.SetToolStreamCallback(func(_ streaming.Frame) bool { called = true; return true })
	if a.toolStreamCb == nil {
		t.Errorf("setter did not install the callback")
	}
	a.toolStreamCb(streaming.Frame{Tool: "x"})
	if !called {
		t.Error("installed callback was not invoked")
	}
	a.SetToolStreamCallback(nil)
	if a.toolStreamCb != nil {
		t.Error("nil setter should detach the callback")
	}
}

// TestDispatchStreaming_ForwardsFramesAndReturnsFinalString pins the
// happy-path of the streaming dispatch wiring: when a tool opts in
// AND the host wired a callback, frames flow through the callback in
// order and the handler's return string becomes the final output.
func TestDispatchStreaming_ForwardsFramesAndReturnsFinalString(t *testing.T) {
	const toolName = "test_streaming_tool"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "fake streaming tool for tests",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			t.Fatal("non-streaming Handler called when StreamHandler should have run")
			return "", nil
		},
		StreamHandler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			sink.Send([]byte("frame-1"))
			sink.Send([]byte("frame-2"))
			sink.Send([]byte("frame-3"))
			return "final-tool-result", nil
		},
	})

	a := &Agent{}
	var mu sync.Mutex
	var seen []string
	a.SetToolStreamCallback(func(f streaming.Frame) bool {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, string(f.Bytes))
		return true
	})

	out, err := a.dispatch(context.Background(), toolName, map[string]any{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if out != "final-tool-result" {
		t.Errorf("output = %q, want final-tool-result", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 3 {
		t.Fatalf("frame count = %d, want 3 (got %v)", len(seen), seen)
	}
	for i, want := range []string{"frame-1", "frame-2", "frame-3"} {
		if seen[i] != want {
			t.Errorf("frame %d = %q, want %q", i, seen[i], want)
		}
	}
}

// TestDispatchStreaming_FallsBackWhenCallbackUnset pins the disabled
// path: with no callback installed, even a Streams=true tool runs
// through the regular Handler path. This is the safe default — no
// behaviour change for hosts that haven't opted in.
func TestDispatchStreaming_FallsBackWhenCallbackUnset(t *testing.T) {
	const toolName = "test_streaming_fallback_tool"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	var streamRan, regularRan bool
	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "fake fallback tool",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			regularRan = true
			return "fallback-result", nil
		},
		StreamHandler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any, _ *streaming.Sink) (string, error) {
			streamRan = true
			return "streamed-result", nil
		},
	})

	a := &Agent{} // toolStreamCb intentionally nil
	out, err := a.dispatch(context.Background(), toolName, map[string]any{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if !regularRan || streamRan {
		t.Errorf("wrong handler ran: regular=%v stream=%v", regularRan, streamRan)
	}
	if out != "fallback-result" {
		t.Errorf("output = %q, want fallback-result", out)
	}
}

// TestDispatchStreaming_FallsBackWhenStreamsFlagFalse pins that a
// tool with Streams=false but a non-nil StreamHandler still runs
// through the regular path. The flag is the explicit opt-in.
func TestDispatchStreaming_FallsBackWhenStreamsFlagFalse(t *testing.T) {
	const toolName = "test_streams_false_tool"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	var streamRan bool
	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "Streams=false tool",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     false, // not opted in
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			return "regular", nil
		},
		StreamHandler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any, _ *streaming.Sink) (string, error) {
			streamRan = true
			return "stream", nil
		},
	})

	a := &Agent{}
	a.SetToolStreamCallback(func(_ streaming.Frame) bool { return true })
	out, _ := a.dispatch(context.Background(), toolName, map[string]any{})
	if streamRan {
		t.Errorf("StreamHandler ran despite Streams=false")
	}
	if out != "regular" {
		t.Errorf("output = %q, want regular", out)
	}
}

// TestDispatchStreaming_NoFramesAfterReturn pins the synchronisation
// guarantee: dispatch waits for the consumer drain to complete so
// no frame is delivered to the callback after dispatch returns.
// Important so observers can assume "dispatch done = all frames
// observed".
func TestDispatchStreaming_NoFramesAfterReturn(t *testing.T) {
	const toolName = "test_streaming_drain_tool"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "drain test",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			return "", nil
		},
		StreamHandler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			for i := 0; i < 50; i++ {
				sink.Send([]byte("x"))
			}
			return "done", nil
		},
	})

	a := &Agent{}
	var mu sync.Mutex
	var count int
	a.SetToolStreamCallback(func(_ streaming.Frame) bool {
		mu.Lock()
		count++
		mu.Unlock()
		return true
	})

	if _, err := a.dispatch(context.Background(), toolName, map[string]any{}); err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	mu.Lock()
	got := count
	mu.Unlock()
	if got != 50 {
		t.Errorf("frame count after dispatch = %d, want 50", got)
	}
}

// TestDispatchStreaming_AbortEarlyOnCallbackFalse pins the consumer-
// driven abort path: when the callback returns false, dispatch
// closes the sink's Aborted() channel and cancels the per-call
// context. A producer that polls Aborted() returns promptly with a
// partial-result string; later frames it would have emitted are
// neither produced nor delivered to the callback.
func TestDispatchStreaming_AbortEarlyOnCallbackFalse(t *testing.T) {
	const toolName = "test_streaming_abort_tool"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	producerSawAbort := make(chan struct{})

	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "abort-aware streaming tool",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			t.Fatal("non-streaming Handler called")
			return "", nil
		},
		StreamHandler: func(ctx context.Context, _ *toolsreg.Deps, _ map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			// Slow producer mirrors a real scan: yields per frame so
			// the consumer can deliver the abort before we run out
			// the 1000-iter safety net.
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for i := 0; i < 1000; i++ {
				select {
				case <-sink.Aborted():
					close(producerSawAbort)
					return "partial-after-abort", nil
				case <-ctx.Done():
					close(producerSawAbort)
					return "ctx-cancelled", ctx.Err()
				case <-ticker.C:
				}
				sink.Send([]byte("tick"))
			}
			t.Fatal("producer never observed abort")
			return "", nil
		},
	})

	a := &Agent{}
	var mu sync.Mutex
	var seen int
	a.SetToolStreamCallback(func(f streaming.Frame) bool {
		mu.Lock()
		defer mu.Unlock()
		seen++
		// Abort after the third frame.
		return seen < 3
	})

	out, err := a.dispatch(context.Background(), toolName, map[string]any{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if out != "partial-after-abort" {
		t.Errorf("output = %q, want partial-after-abort", out)
	}
	select {
	case <-producerSawAbort:
	default:
		t.Fatal("producer did not observe abort signal")
	}
	mu.Lock()
	defer mu.Unlock()
	// We aborted *after* the third invocation returned false, so the
	// callback must have seen exactly 3 frames. Any drained-after-
	// abort frames are silently swallowed (no callback invocation).
	if seen != 3 {
		t.Errorf("callback invoked %d times, want 3", seen)
	}
}

// TestDispatchStreaming_AbortCancelsContext pins the second half of
// the abort contract: the per-call context is cancelled. Producers
// that watch ctx.Done() instead of sink.Aborted() must also observe
// the abort. Belt-and-suspenders so existing context-aware tools
// work without retrofitting the Aborted() poll.
func TestDispatchStreaming_AbortCancelsContext(t *testing.T) {
	const toolName = "test_streaming_abort_ctx_tool"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	producerSawCancel := make(chan struct{})

	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "ctx-aware streaming tool",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			return "", nil
		},
		StreamHandler: func(ctx context.Context, _ *toolsreg.Deps, _ map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			// Slow producer (1 ms per frame) — mirrors a real radio
			// scan and gives the consumer goroutine room to deliver
			// the cancel signal before the producer finishes.
			ticker := time.NewTicker(time.Millisecond)
			defer ticker.Stop()
			for i := 0; i < 1000; i++ {
				select {
				case <-ctx.Done():
					close(producerSawCancel)
					return "ctx-aware-partial", nil
				case <-ticker.C:
				}
				sink.Send([]byte("frame"))
			}
			t.Fatal("producer never observed ctx cancel")
			return "", nil
		},
	})

	a := &Agent{}
	var mu sync.Mutex
	abortAfter := 1
	count := 0
	a.SetToolStreamCallback(func(_ streaming.Frame) bool {
		mu.Lock()
		defer mu.Unlock()
		count++
		return count <= abortAfter
	})

	out, err := a.dispatch(context.Background(), toolName, map[string]any{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if out != "ctx-aware-partial" {
		t.Errorf("output = %q, want ctx-aware-partial", out)
	}
	select {
	case <-producerSawCancel:
	default:
		t.Fatal("producer did not observe ctx cancellation")
	}
}

// TestDispatchStreaming_StubbornProducerIsNotForceKilled pins that
// abort is cooperative: a producer that ignores both signals runs
// to completion, drained-after-abort frames are silently swallowed,
// and dispatch returns the producer's normal final string. This is
// the documented contract — the alternative (forced kill) would
// risk leaving hardware in a half-configured state.
func TestDispatchStreaming_StubbornProducerIsNotForceKilled(t *testing.T) {
	const toolName = "test_streaming_stubborn_tool"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	const totalFrames = 20
	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "stubborn tool that ignores abort",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			return "", nil
		},
		StreamHandler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			for i := 0; i < totalFrames; i++ {
				sink.Send([]byte("ignored"))
			}
			return "ran-to-completion", nil
		},
	})

	a := &Agent{}
	var seen int
	a.SetToolStreamCallback(func(_ streaming.Frame) bool {
		seen++
		return false // abort on first frame
	})

	out, err := a.dispatch(context.Background(), toolName, map[string]any{})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}
	if out != "ran-to-completion" {
		t.Errorf("output = %q, want ran-to-completion", out)
	}
	if seen != 1 {
		t.Errorf("callback invoked %d times after abort, want exactly 1", seen)
	}
}

// TestDispatchStreaming_PanickingCallbackDoesNotCrashAgent pins the
// v0.93 fix. The consumer goroutine in dispatchStreaming used to
// call the host callback directly without recover, so a panicking
// host (REPL UI writing to a closed terminal, web cockpit losing
// its WebSocket mid-stream) crashed the agent process. The
// sibling toolStatusCb already had safeCallToolStatus for exactly
// this reason; the streaming path drifted.
//
// The recovered panic is now treated the same as a `false` return
// from the callback — abort the stream, drain remaining frames
// silently, dispatchStreaming completes cleanly. We assert:
//  1. dispatch returns (no panic propagates).
//  2. The handler runs to completion (drain proceeded after the
//     panic).
//  3. The callback was invoked at most once (we abort on the
//     panicking frame).
func TestDispatchStreaming_PanickingCallbackDoesNotCrashAgent(t *testing.T) {
	const toolName = "test_streaming_panic_cb"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	const totalFrames = 5
	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "tool whose stream consumer panics",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			return "", nil
		},
		StreamHandler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any, sink *streaming.Sink) (string, error) {
			defer sink.Close()
			for i := 0; i < totalFrames; i++ {
				sink.Send([]byte("frame"))
			}
			return "completed-after-panic", nil
		},
	})

	a := &Agent{}
	var seen int
	a.SetToolStreamCallback(func(_ streaming.Frame) bool {
		seen++
		panic("simulated host crash mid-stream")
	})

	out, err := a.dispatch(context.Background(), toolName, map[string]any{})
	if err != nil {
		t.Fatalf("dispatch: %v — panic in callback shouldn't propagate as error", err)
	}
	if out != "completed-after-panic" {
		t.Errorf("output = %q, want completed-after-panic — drain didn't proceed", out)
	}
	if seen != 1 {
		t.Errorf("callback invoked %d times after panic, want exactly 1 (panic should abort the stream)", seen)
	}
}

// TestDispatchStreaming_PanickingHandlerWithoutDeferCloseDoesNotLeak pins
// the dispatch-level safety net for a handler that panics WITHOUT
// having deferred sink.Close. The streaming.Handler docstring says
// handlers MUST defer Close, and every production handler does — but
// trusting that for every future tool would leave one missed defer
// away from a permanent goroutine stuck on `range sink.Frames()`.
//
// Pre-fix: dispatchStreaming called `sink.Close()` and `<-done`
// INLINE after the StreamHandler returned. When the handler panicked
// without deferring Close, those statements were bypassed; the
// consumer goroutine ranged forever on a never-closed channel and
// dispatch returned with that goroutine still alive.
//
// Post-fix: sink.Close + <-done moved into a `defer` so they fire
// on both the normal-return and panic paths.
//
// The test detects the leak by comparing runtime.NumGoroutine before
// and after dispatch. Pre-fix the consumer goroutine survives forever
// so the count stays elevated; post-fix it drops back to baseline.
// A short polling loop accommodates the scheduler — Go doesn't reap
// exiting goroutines synchronously.
func TestDispatchStreaming_PanickingHandlerWithoutDeferCloseDoesNotLeak(t *testing.T) {
	const toolName = "test_streaming_handler_panic_no_close"
	t.Cleanup(func() { toolsreg.UnregisterForTest(toolName) })

	toolsreg.Register(toolsreg.Spec{
		Name:        toolName,
		Description: "streaming handler that panics without closing the sink",
		Schema:      json.RawMessage(`{"type":"object"}`),
		Risk:        risk.Low,
		Streams:     true,
		Handler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any) (string, error) {
			return "", nil
		},
		StreamHandler: func(_ context.Context, _ *toolsreg.Deps, _ map[string]any, sink *streaming.Sink) (string, error) {
			// Intentionally NO defer sink.Close — simulate a buggy
			// or newly-added tool that violates the docstring's
			// "MUST defer" rule. The dispatch layer's safety net
			// is the load-bearing piece this test exercises.
			sink.Send([]byte("one-frame"))
			panic("simulated handler crash before defer close")
		},
	})

	a := &Agent{}
	a.SetToolStreamCallback(func(_ streaming.Frame) bool { return true })

	// Settle: yield so any background goroutines spawned by earlier tests
	// (HTTP clients, sqlite WAL writers, etc.) have a chance to exit
	// before we snapshot the baseline.
	runtime.Gosched()
	time.Sleep(50 * time.Millisecond)
	before := runtime.NumGoroutine()

	_, err := a.dispatch(context.Background(), toolName, map[string]any{})
	if err == nil {
		t.Fatalf("expected panic-wrapped error from dispatch, got nil")
	}

	// Poll for goroutine cleanup. Pre-fix the consumer is stuck
	// ranging on the never-closed sink forever, so count stays > before.
	// Post-fix it exits as soon as dispatch's deferred sink.Close runs.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("consumer goroutine leaked after panic: %d goroutines before dispatch, %d still alive 2s after — the dispatchStreaming sink.Close + drain didn't run on the panic path",
		before, runtime.NumGoroutine())
}
