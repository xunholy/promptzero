package agent

import (
	"context"
	"encoding/json"
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
