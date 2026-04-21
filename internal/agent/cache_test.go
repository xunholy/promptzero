package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// TestBuildCachedRequest_SystemBreakpoint verifies the system prompt
// carries an ephemeral cache_control breakpoint. This is the primary
// cache anchor — mis-configure it and every turn pays full input-token
// price.
func TestBuildCachedRequest_SystemBreakpoint(t *testing.T) {
	params := buildCachedRequest("claude-sonnet-4-6", "you are PromptZero", nil, nil)
	if len(params.System) != 1 {
		t.Fatalf("expected 1 system block, got %d", len(params.System))
	}
	sys := params.System[0]

	body, err := json.Marshal(sys)
	if err != nil {
		t.Fatalf("marshal system block: %v", err)
	}
	if !strings.Contains(string(body), `"cache_control"`) {
		t.Fatalf("system block missing cache_control: %s", body)
	}
	if !strings.Contains(string(body), `"ephemeral"`) {
		t.Fatalf("system block missing ephemeral type: %s", body)
	}
}

// TestBuildCachedRequest_LastToolBreakpoint verifies only the *last*
// tool in the catalog has a cache_control breakpoint. Placing it there
// caches the entire tool block (plus the system prompt before it) with
// a single breakpoint, honouring the 4-breakpoint-per-request ceiling.
func TestBuildCachedRequest_LastToolBreakpoint(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("first_tool", "first", nil),
		tool("middle_tool", "middle", nil),
		tool("last_tool", "last", nil),
	}
	params := buildCachedRequest("claude-sonnet-4-6", "sys", tools, nil)
	if len(params.Tools) != 3 {
		t.Fatalf("tool count changed: got %d, want 3", len(params.Tools))
	}

	// First two must NOT carry cache_control.
	for i, name := range []string{"first_tool", "middle_tool"} {
		raw, _ := json.Marshal(params.Tools[i])
		if strings.Contains(string(raw), `"cache_control"`) {
			t.Errorf("tool %d (%s) should not carry cache_control: %s", i, name, raw)
		}
	}

	// Last tool MUST carry cache_control: ephemeral.
	raw, _ := json.Marshal(params.Tools[2])
	if !strings.Contains(string(raw), `"cache_control"`) {
		t.Errorf("last tool missing cache_control: %s", raw)
	}
	if !strings.Contains(string(raw), `"ephemeral"`) {
		t.Errorf("last tool missing ephemeral type: %s", raw)
	}
}

// TestBuildCachedRequest_DoesNotMutateInputTools makes sure our
// breakpoint attachment clones instead of mutating the caller's catalog
// — the tool builders return package-level slices and we must not
// scribble on them.
func TestBuildCachedRequest_DoesNotMutateInputTools(t *testing.T) {
	tools := []anthropic.ToolUnionParam{
		tool("only_tool", "only", nil),
	}
	// Snapshot the input tool's json shape before the call.
	before, _ := json.Marshal(tools[0])

	_ = buildCachedRequest("claude-sonnet-4-6", "sys", tools, nil)

	after, _ := json.Marshal(tools[0])
	if string(before) != string(after) {
		t.Fatalf("input tool was mutated:\nbefore=%s\nafter=%s", before, after)
	}
}

// TestBuildCachedRequest_ModelAndMessages forwards the remaining fields
// untouched.
func TestBuildCachedRequest_ModelAndMessages(t *testing.T) {
	history := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("hi")),
	}
	params := buildCachedRequest("claude-opus-4-7", "sys", nil, history)
	if string(params.Model) != "claude-opus-4-7" {
		t.Errorf("Model = %s, want claude-opus-4-7", params.Model)
	}
	if len(params.Messages) != 1 {
		t.Errorf("history length = %d, want 1", len(params.Messages))
	}
	if params.MaxTokens <= 0 {
		t.Errorf("MaxTokens = %d, must be positive", params.MaxTokens)
	}
}
