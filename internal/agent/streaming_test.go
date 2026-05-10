package agent

import (
	"context"
	"encoding/json"
	"sync"
	"testing"

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
	a.SetToolStreamCallback(func(_ streaming.Frame) { called = true })
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
	a.SetToolStreamCallback(func(f streaming.Frame) {
		mu.Lock()
		defer mu.Unlock()
		seen = append(seen, string(f.Bytes))
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
	a.SetToolStreamCallback(func(_ streaming.Frame) {})
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
	a.SetToolStreamCallback(func(_ streaming.Frame) {
		mu.Lock()
		count++
		mu.Unlock()
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
