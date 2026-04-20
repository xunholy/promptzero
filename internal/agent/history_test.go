package agent

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// makeToolPair appends a matched assistant tool_use + user tool_result pair to h.
func makeToolPair(h []anthropic.MessageParam, id string) []anthropic.MessageParam {
	h = append(h, anthropic.NewAssistantMessage(
		anthropic.ContentBlockParamUnion{
			OfToolUse: &anthropic.ToolUseBlockParam{
				ID:    id,
				Name:  "device_info",
				Input: json.RawMessage(`{}`),
			},
		},
	))
	h = append(h, anthropic.NewUserMessage(
		anthropic.NewToolResultBlock(id, "ok", false),
	))
	return h
}

// TestCompactHistoryLocked_BasicTrim verifies that after building a history
// 3x larger than maxHistory and calling compactHistoryLocked, the result
// stays within maxHistory+small slack, and the first 2 anchor entries are
// preserved.
func TestCompactHistoryLocked_BasicTrim(t *testing.T) {
	a := &Agent{}

	// Seed the first 2 anchor entries.
	a.history = append(a.history,
		anthropic.NewUserMessage(anthropic.NewTextBlock("anchor-0")),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("anchor-1")),
	)

	// Build 3x maxHistory additional entries using paired tool_use/tool_result.
	for i := 0; i < 3*maxHistory; i++ {
		a.history = makeToolPair(a.history, fmt.Sprintf("t%d", i))
	}

	// Single compaction call.
	a.compactHistoryLocked()

	// len must be ≤ maxHistory + small slack (2 for one extra pair retained
	// to honour the no-split invariant).
	if len(a.history) > maxHistory+2 {
		t.Errorf("history length %d exceeds maxHistory+2 (%d)", len(a.history), maxHistory+2)
	}

	// First 2 anchor entries must still be present.
	if len(a.history) < 2 {
		t.Fatal("history has fewer than 2 entries after compaction")
	}
	if a.history[0].Content[0].OfText == nil || a.history[0].Content[0].OfText.Text != "anchor-0" {
		t.Errorf("anchor entry 0 was clobbered: %+v", a.history[0])
	}
	if a.history[1].Content[0].OfText == nil || a.history[1].Content[0].OfText.Text != "anchor-1" {
		t.Errorf("anchor entry 1 was clobbered: %+v", a.history[1])
	}
}

// TestCompactHistoryLocked_NoPairSplit verifies that no tool_use message in
// the result is without its paired tool_result immediately following it.
func TestCompactHistoryLocked_NoPairSplit(t *testing.T) {
	a := &Agent{}

	a.history = append(a.history,
		anthropic.NewUserMessage(anthropic.NewTextBlock("anchor-0")),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("anchor-1")),
	)

	// Build 2x maxHistory tool pairs, then compact once.
	for i := 0; i < 2*maxHistory; i++ {
		a.history = makeToolPair(a.history, fmt.Sprintf("t%d", i))
	}
	a.compactHistoryLocked()

	// Scan for orphaned tool_use (an assistant message with tool_use not
	// immediately followed by a user message containing only tool_result blocks).
	for i, msg := range a.history {
		if msg.Role != anthropic.MessageParamRoleAssistant {
			continue
		}
		for _, b := range msg.Content {
			if b.OfToolUse == nil {
				continue
			}
			// Must have a next message that is a user tool_result.
			if i+1 >= len(a.history) {
				t.Errorf("tool_use at index %d has no following message", i)
				break
			}
			next := a.history[i+1]
			if next.Role != anthropic.MessageParamRoleUser || !allToolResults(next) {
				t.Errorf("tool_use at index %d is not followed by a tool_result user message", i)
			}
			break
		}
	}
}

// TestCompactHistoryLocked_NoopBelowMax verifies compaction is a no-op when
// history is within the limit.
func TestCompactHistoryLocked_NoopBelowMax(t *testing.T) {
	a := &Agent{}
	for i := 0; i < maxHistory; i++ {
		a.history = append(a.history,
			anthropic.NewUserMessage(anthropic.NewTextBlock("u")),
		)
	}
	before := len(a.history)
	a.compactHistoryLocked()
	if len(a.history) != before {
		t.Errorf("expected no-op, got len %d (was %d)", len(a.history), before)
	}
}
