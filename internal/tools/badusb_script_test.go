package tools

import (
	"context"
	"strings"
	"testing"
)

// TestBadUSBScriptParseHandler_HappyPath confirms the Spec
// handler parses a typical "open Run, type notepad, hit enter"
// payload through to JSON without issues.
func TestBadUSBScriptParseHandler_HappyPath(t *testing.T) {
	src := "REM open Run\nDELAY 500\nGUI r\nDELAY 200\nSTRING notepad\nENTER\n"
	out, err := badusbScriptParseHandler(context.Background(), nil, map[string]any{
		"script": src,
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"issue_count": 0`) {
		t.Errorf("expected issue_count 0 in output:\n%s", out)
	}
	if !strings.Contains(out, `"command_count": 5`) {
		t.Errorf("expected command_count 5:\n%s", out)
	}
	if !strings.Contains(out, `"estimated_total_ms": 707`) {
		t.Errorf("expected estimated_total_ms 707:\n%s", out)
	}
}

// TestBadUSBScriptParseHandler_InvalidScript confirms that an
// unrecognised command shows up as an issue.
func TestBadUSBScriptParseHandler_InvalidScript(t *testing.T) {
	out, err := badusbScriptParseHandler(context.Background(), nil, map[string]any{
		"script": "DELAY 100\nFROBNICATE\n",
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"issue_count": 1`) {
		t.Errorf("expected issue_count 1:\n%s", out)
	}
	if !strings.Contains(out, "unknown") {
		t.Errorf("expected 'unknown' in issue message:\n%s", out)
	}
}

func TestBadUSBScriptParseHandler_RejectsEmpty(t *testing.T) {
	_, err := badusbScriptParseHandler(context.Background(), nil, map[string]any{"script": ""})
	if err == nil {
		t.Fatal("want error for empty script")
	}
}
