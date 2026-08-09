package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	toolsreg "github.com/xunholy/promptzero/internal/tools"
)

// TestSuggestToolNames_SurfacesRealTools verifies a near-miss tool name is
// mapped back to real, callable registry tools — the "did you mean" path
// that enriches an unknown_tool error. "nfc_readd" is not a registered
// tool, but its "nfc" token (and the ranker's domain synonyms) must pull
// genuine nfc/mifare-family tools, every one of which the model can then
// actually call.
func TestSuggestToolNames_SurfacesRealTools(t *testing.T) {
	got := suggestToolNames("nfc_readd", 3)
	if len(got) == 0 {
		t.Fatal("suggestToolNames returned no candidates for a near-miss nfc name")
	}
	if len(got) > 3 {
		t.Fatalf("suggestToolNames returned %d candidates, want <= 3", len(got))
	}
	for _, name := range got {
		if _, ok := toolsreg.Get(name); !ok {
			t.Errorf("suggestion %q is not a registered tool — a 'did you mean' must be callable", name)
		}
	}
}

// TestSuggestToolNames_NoSharedToken verifies a name that shares no token
// with any registered tool returns nil rather than fabricating a match —
// the caller then falls back to the generic catalog remediation.
func TestSuggestToolNames_NoSharedToken(t *testing.T) {
	if got := suggestToolNames("florblegorpxyzzy", 3); len(got) != 0 {
		t.Errorf("suggestToolNames = %v, want empty for a nonsense name", got)
	}
}

// TestSuggestToolNames_Degenerate covers the empty-input and non-positive
// limit guards.
func TestSuggestToolNames_Degenerate(t *testing.T) {
	if got := suggestToolNames("", 3); got != nil {
		t.Errorf("empty name: got %v, want nil", got)
	}
	if got := suggestToolNames("nfc_read", 0); got != nil {
		t.Errorf("zero limit: got %v, want nil", got)
	}
}

// TestExecuteTool_UnknownToolEmitsDidYouMean is the end-to-end wiring
// check: an unknown tool name that shares a token with a real family
// must come back as a structured tool error whose remediation carries a
// "did you mean" hint, so the model self-corrects on its next turn.
func TestExecuteTool_UnknownToolEmitsDidYouMean(t *testing.T) {
	a := agentForModelTest("claude-sonnet-4-6", nil)
	out, isErr := a.executeTool(context.Background(), "nfc_readd", json.RawMessage(`{}`))
	if !isErr {
		t.Fatalf("unknown tool must surface as a tool error; got success: %q", out)
	}
	var te ToolError
	if err := json.Unmarshal([]byte(out), &te); err != nil {
		t.Fatalf("tool error is not valid JSON: %v\n%s", err, out)
	}
	if te.Code != "unknown_tool" {
		t.Fatalf("Code = %q, want unknown_tool", te.Code)
	}
	joined := strings.Join(te.Remediation, " ")
	if !strings.Contains(joined, "did you mean") {
		t.Errorf("remediation missing 'did you mean' hint: %v", te.Remediation)
	}
}

// TestSuggestToolNames_NeverEchoesExact guards the defensive branch: a
// real tool name passed in must not be returned as a suggestion of
// itself (the enrichment only fires on an unknown name, but the guard
// keeps a future caller honest).
func TestSuggestToolNames_NeverEchoesExact(t *testing.T) {
	for _, name := range suggestToolNames("tool_search", 5) {
		if name == "tool_search" {
			t.Errorf("suggestToolNames echoed the exact input name %q", name)
		}
	}
}
