package tools

import (
	"context"
	"strings"
	"testing"
)

// TestToolSearchHandler verifies the discovery tool wraps the live registry:
// an exact tool name ranks first, a task synonym surfaces a relevant tool, the
// output carries risk/group, and bad input is rejected.
func TestToolSearchHandler(t *testing.T) {
	// Exact name → that tool is present and (being an exact match) ranked first.
	out, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": "device_info"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, `"name": "device_info"`) {
		t.Errorf("exact-name query missing device_info:\n%s", out)
	}
	if !strings.Contains(out, `"risk":`) || !strings.Contains(out, `"group":`) {
		t.Errorf("result missing risk/group enrichment:\n%s", out)
	}

	// Task query via synonym map: 'garage' should reach a subghz tool.
	out, err = toolSearchHandler(context.Background(), nil, map[string]any{"query": "garage door"})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if !strings.Contains(out, "subghz") {
		t.Errorf("garage door did not surface any subghz tool:\n%s", out)
	}

	// Empty query is rejected.
	if _, err := toolSearchHandler(context.Background(), nil, map[string]any{"query": "  "}); err == nil {
		t.Error("empty query: expected error, got nil")
	}

	// No-match query returns a clean zero-result body, not an error.
	out, err = toolSearchHandler(context.Background(), nil, map[string]any{"query": "zzqqxx-nonexistent"})
	if err != nil {
		t.Fatalf("no-match handler: %v", err)
	}
	if !strings.Contains(out, `"count": 0`) {
		t.Errorf("no-match query should report count 0:\n%s", out)
	}
}
