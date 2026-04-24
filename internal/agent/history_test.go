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

// TestCompactHistoryLocked_AnchorWithToolUseExtended pins the cliyolo
// regression: the very first assistant turn invokes a tool, so a.history[1]
// is an assistant tool_use whose matching tool_result lives at a.history[2].
// Before the fix, compaction's hardcoded anchor a.history[:2] dropped the
// tool_result, leaving an orphan tool_use at messages.1 — every subsequent
// API call returned 400 with "tool_use ids were found without tool_result
// blocks immediately after". The cliyolo run hit this at prompt 24/35 once
// the live session crossed maxHistory.
func TestCompactHistoryLocked_AnchorWithToolUseExtended(t *testing.T) {
	a := &Agent{}

	// Anchor: the first user prompt → assistant tool_use → user tool_result
	// triple. This is what every cliyolo session produces because the
	// first prompt typically asks for device info.
	a.history = append(a.history,
		anthropic.NewUserMessage(anthropic.NewTextBlock("Get the Flipper device info.")),
	)
	a.history = makeToolPair(a.history, "anchor-tool-id")

	// Saturate the rest with tool pairs so compaction triggers.
	for i := 0; i < 2*maxHistory; i++ {
		a.history = makeToolPair(a.history, fmt.Sprintf("t%d", i))
	}

	a.compactHistoryLocked()

	// Critical invariant: every tool_use in the kept history MUST be
	// followed by its matching tool_result. The bug previously failed
	// at index 1.
	for i, msg := range a.history {
		if msg.Role != anthropic.MessageParamRoleAssistant {
			continue
		}
		for _, b := range msg.Content {
			if b.OfToolUse == nil {
				continue
			}
			if i+1 >= len(a.history) {
				t.Fatalf("tool_use at index %d has no following message", i)
			}
			next := a.history[i+1]
			if next.Role != anthropic.MessageParamRoleUser || !allToolResults(next) {
				t.Errorf("tool_use at index %d not followed by tool_result message: %+v", i, next)
			}
			// Also verify the tool_use_id at next matches the one at this
			// index — order matters for the API check.
			if b.OfToolUse.ID == "anchor-tool-id" {
				if next.Content[0].OfToolResult == nil || next.Content[0].OfToolResult.ToolUseID != "anchor-tool-id" {
					t.Errorf("anchor's tool_use_id %q not matched by the next user message", b.OfToolUse.ID)
				}
			}
			break
		}
	}

	// First user anchor entry must still be present (we do extend, not
	// drop, when a clean tool_result is available).
	if len(a.history) < 1 {
		t.Fatal("history empty after compaction")
	}
	if a.history[0].Content[0].OfText == nil ||
		a.history[0].Content[0].OfText.Text != "Get the Flipper device info." {
		t.Errorf("first anchor entry was clobbered: %+v", a.history[0])
	}
}

// TestCompactHistoryLocked_AnchorMalformedDropsAnchor verifies that when
// a.history[1] has a tool_use but a.history[2] is NOT the matching
// tool_result (a malformed history), compaction drops the anchor entirely
// rather than shipping a corrupt payload.
func TestCompactHistoryLocked_AnchorMalformedDropsAnchor(t *testing.T) {
	a := &Agent{}

	// a.history[0]: user
	// a.history[1]: assistant tool_use
	// a.history[2]: user TEXT (not a tool_result) — broken pairing
	a.history = append(a.history,
		anthropic.NewUserMessage(anthropic.NewTextBlock("seed user")),
		anthropic.NewAssistantMessage(anthropic.ContentBlockParamUnion{
			OfToolUse: &anthropic.ToolUseBlockParam{
				ID:    "orphan-tool",
				Name:  "device_info",
				Input: json.RawMessage(`{}`),
			},
		}),
		anthropic.NewUserMessage(anthropic.NewTextBlock("not a tool_result")),
	)
	for i := 0; i < 2*maxHistory; i++ {
		a.history = makeToolPair(a.history, fmt.Sprintf("t%d", i))
	}

	a.compactHistoryLocked()

	// The kept history must NOT begin with the orphan tool_use.
	for i, msg := range a.history {
		if msg.Role != anthropic.MessageParamRoleAssistant {
			continue
		}
		for _, b := range msg.Content {
			if b.OfToolUse != nil && b.OfToolUse.ID == "orphan-tool" {
				t.Errorf("orphan tool_use %q kept in compacted history at index %d", b.OfToolUse.ID, i)
			}
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
