package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/anthropics/anthropic-sdk-go"
)

// stubHistory builds a small synthetic history exercising every
// handoff heuristic at once: two user turns with an assistant reply in
// between, a successful tool pair, and a failing tool pair whose
// result is structured ToolError JSON.
func stubHistory() []anthropic.MessageParam {
	failingBody := ToolError{
		Code:      "flipper_nfc_timeout",
		Tool:      "nfc_detect",
		Message:   "timeout after 30s",
		Retryable: true,
	}.JSON()

	return []anthropic.MessageParam{
		// Turn 1: user asks to scan wifi, assistant calls wifi_scan_ap
		anthropic.NewUserMessage(anthropic.NewTextBlock("scan the nearest AP")),
		{
			Role: anthropic.MessageParamRoleAssistant,
			Content: []anthropic.ContentBlockParamUnion{{
				OfToolUse: &anthropic.ToolUseBlockParam{
					ID:    "toolu_1",
					Name:  "wifi_scan_ap",
					Input: json.RawMessage(`{"duration_seconds":10}`),
				},
			}},
		},
		// Tool result: successful.
		anthropic.NewUserMessage(anthropic.NewToolResultBlock("toolu_1", "found 3 APs: home, guest, office", false)),
		// Assistant replies with text ("thread resolved").
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("found 3 APs, which should I target?")),

		// Turn 2: user asks for NFC read; assistant tries nfc_detect.
		anthropic.NewUserMessage(anthropic.NewTextBlock("now read the access badge")),
		{
			Role: anthropic.MessageParamRoleAssistant,
			Content: []anthropic.ContentBlockParamUnion{{
				OfToolUse: &anthropic.ToolUseBlockParam{
					ID:    "toolu_2",
					Name:  "nfc_detect",
					Input: json.RawMessage(`{"timeout_seconds":30}`),
				},
			}},
		},
		// Tool result: structured error.
		anthropic.NewUserMessage(anthropic.NewToolResultBlock("toolu_2", failingBody, true)),
	}
}

func TestBuildHandoff_Findings(t *testing.T) {
	h := BuildHandoff(stubHistory())
	if len(h.Findings) != 2 {
		t.Fatalf("Findings len = %d, want 2: %+v", len(h.Findings), h.Findings)
	}
	names := map[string]int{}
	for _, f := range h.Findings {
		names[f.Tool] = f.Count
	}
	if names["wifi_scan_ap"] != 1 {
		t.Errorf("wifi_scan_ap count = %d, want 1", names["wifi_scan_ap"])
	}
	if names["nfc_detect"] != 1 {
		t.Errorf("nfc_detect count = %d, want 1", names["nfc_detect"])
	}
	// LastSeen for wifi should carry the success preview.
	for _, f := range h.Findings {
		if f.Tool == "wifi_scan_ap" && !strings.Contains(f.LastSeen, "found 3 APs") {
			t.Errorf("wifi_scan_ap last_seen should carry preview: %q", f.LastSeen)
		}
	}
}

func TestBuildHandoff_Blocked_StructuredError(t *testing.T) {
	h := BuildHandoff(stubHistory())
	if len(h.Blocked) != 1 {
		t.Fatalf("Blocked len = %d, want 1: %+v", len(h.Blocked), h.Blocked)
	}
	b := h.Blocked[0]
	if b.Tool != "nfc_detect" {
		t.Errorf("Blocked[0].Tool = %q, want nfc_detect", b.Tool)
	}
	if b.Code != "flipper_nfc_timeout" {
		t.Errorf("Blocked[0].Code = %q, want flipper_nfc_timeout (ToolError JSON should parse)", b.Code)
	}
}

func TestBuildHandoff_OpenThread(t *testing.T) {
	// The second user turn ("now read the access badge") is followed
	// by a tool call (no text reply), so it should remain open.
	h := BuildHandoff(stubHistory())
	if len(h.OpenThreads) != 1 {
		t.Fatalf("expected 1 open thread, got %d", len(h.OpenThreads))
	}
	if !strings.Contains(h.OpenThreads[0].Text, "access badge") {
		t.Errorf("open thread text = %q, want contains 'access badge'", h.OpenThreads[0].Text)
	}
}

func TestBuildHandoff_TurnsCovered(t *testing.T) {
	h := BuildHandoff(stubHistory())
	if h.TurnsCovered != len(stubHistory()) {
		t.Fatalf("TurnsCovered = %d, want %d", h.TurnsCovered, len(stubHistory()))
	}
}

func TestBuildHandoff_JSONRoundTrip(t *testing.T) {
	h := BuildHandoff(stubHistory())
	js := h.JSON()
	// Schema invariants — every field the spec commits to must appear.
	for _, want := range []string{`"findings"`, `"open_threads"`, `"blocked"`, `"turns_covered"`, `"generated_at"`} {
		if !strings.Contains(js, want) {
			t.Errorf("handoff JSON missing %q: %s", want, js)
		}
	}
	var decoded HandoffArtifact
	if err := json.Unmarshal([]byte(js), &decoded); err != nil {
		t.Fatalf("handoff JSON did not round-trip: %v", err)
	}
	if decoded.TurnsCovered != h.TurnsCovered {
		t.Errorf("round-trip turns_covered mismatch: %d vs %d", decoded.TurnsCovered, h.TurnsCovered)
	}
}

func TestBuildHandoff_EmptyHistory(t *testing.T) {
	h := BuildHandoff(nil)
	if h.TurnsCovered != 0 {
		t.Errorf("empty history -> TurnsCovered = %d, want 0", h.TurnsCovered)
	}
	if len(h.Findings) != 0 || len(h.OpenThreads) != 0 || len(h.Blocked) != 0 {
		t.Errorf("empty history should have all-zero slices: %+v", h)
	}
	// GeneratedAt still populates — useful for proving the snapshot
	// was taken even on empty sessions.
	if h.GeneratedAt.IsZero() {
		t.Errorf("GeneratedAt should be set even on empty history")
	}
}

func TestBuildHandoff_IgnoresSyntheticPrefixes(t *testing.T) {
	// The state-oracle block injected on every turn must not pollute
	// OpenThreads with noise like "<device-state>...".
	hist := []anthropic.MessageParam{
		anthropic.NewUserMessage(anthropic.NewTextBlock("<device-state>\n{\"fork\":\"Momentum\"}\n</device-state>\n\nwhat's connected?")),
		anthropic.NewAssistantMessage(anthropic.NewTextBlock("Momentum 0.99.1, battery 84%.")),
	}
	h := BuildHandoff(hist)
	// Assistant replied, so the user turn is closed — no open threads.
	if len(h.OpenThreads) != 0 {
		t.Fatalf("open thread should have cleared after assistant reply, got %+v", h.OpenThreads)
	}
}
