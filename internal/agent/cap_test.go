package agent

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/testmocks"
)

// TestRunToolCallCap builds an agent wired to a mock Anthropic server
// that keeps returning tool_use blocks forever, lowers the per-turn cap,
// and asserts Run terminates with the synthetic cap-reached message —
// proving the guard short-circuits runaway tool loops.
func TestRunToolCallCap(t *testing.T) {
	script := make([]testmocks.AnthropicScript, 0, 16)
	for i := 0; i < 16; i++ {
		script = append(script, testmocks.AnthropicScript{
			Tool:      "fake_tool_for_cap_test",
			ToolInput: map[string]any{},
		})
	}
	client := testmocks.NewMockAnthropic(t, script)

	cfg := &config.Config{Model: "claude-mock"}
	a := New(client, nil, cfg)
	a.SetMaxToolsPerTurn(3)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct {
		out string
		err error
	}, 1)
	go func() {
		out, err := a.Run(ctx, "keep calling tools forever")
		done <- struct {
			out string
			err error
		}{out, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Run: %v", r.err)
		}
		if !strings.Contains(r.out, "cap reached") {
			t.Fatalf("Run output missing cap sentinel: %q", r.out)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Run did not terminate within deadline — cap guard failed")
	}
}

// TestSetMaxToolsPerTurnResetsOnNonPositive verifies that passing 0 or a
// negative value restores the default cap, so callers that fumble the
// knob don't end up with a permanently disabled guard.
func TestSetMaxToolsPerTurnResetsOnNonPositive(t *testing.T) {
	cfg := &config.Config{Model: "claude-mock"}
	a := New(nil, nil, cfg)
	a.SetMaxToolsPerTurn(5)
	if a.maxToolsPerTurn != 5 {
		t.Fatalf("want maxToolsPerTurn=5, got %d", a.maxToolsPerTurn)
	}
	a.SetMaxToolsPerTurn(0)
	if a.maxToolsPerTurn != defaultMaxToolCallsPerTurn {
		t.Fatalf("want reset to default (%d), got %d", defaultMaxToolCallsPerTurn, a.maxToolsPerTurn)
	}
	a.SetMaxToolsPerTurn(-1)
	if a.maxToolsPerTurn != defaultMaxToolCallsPerTurn {
		t.Fatalf("want reset to default after negative, got %d", a.maxToolsPerTurn)
	}
}
