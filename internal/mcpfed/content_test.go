package mcpfed

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestExtractText_TextContent(t *testing.T) {
	res := &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Text: "hello"},
			mcp.TextContent{Text: "world"},
		},
	}
	got, err := extractText(res, 1<<20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "hello\nworld" {
		t.Errorf("got %q, want %q", got, "hello\nworld")
	}
}

func TestExtractText_StructuredPreferred(t *testing.T) {
	res := &mcp.CallToolResult{
		Content:           []mcp.Content{mcp.TextContent{Text: "fallback text"}},
		StructuredContent: map[string]any{"key": "value", "n": 42},
	}
	got, err := extractText(res, 1<<20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, `"key":"value"`) || !strings.Contains(got, `"n":42`) {
		t.Errorf("structured render missing fields, got %q", got)
	}
	if strings.Contains(got, "fallback text") {
		t.Errorf("text content leaked when structured present: %q", got)
	}
}

func TestExtractText_IsErrorReturnsError(t *testing.T) {
	res := &mcp.CallToolResult{
		IsError: true,
		Content: []mcp.Content{mcp.TextContent{Text: "bad input"}},
	}
	_, err := extractText(res, 1<<20)
	if err == nil {
		t.Fatalf("expected error for IsError=true")
	}
	if !strings.Contains(err.Error(), "bad input") {
		t.Errorf("error did not include body: %v", err)
	}
}

func TestExtractText_Nil(t *testing.T) {
	_, err := extractText(nil, 1<<20)
	if err == nil {
		t.Fatalf("expected error for nil result")
	}
}

func TestExtractText_ImagePlaceholder(t *testing.T) {
	res := &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Text: "see image"},
			mcp.ImageContent{MIMEType: "image/png", Data: "AAAA"},
		},
	}
	got, err := extractText(res, 1<<20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "[image: image/png") {
		t.Errorf("image placeholder missing from %q", got)
	}
}

// TestExtractText_Truncates bounds a runaway/malicious federated server: a
// body past the cap is truncated with a marker rather than passed through
// whole into the agent's LLM context / audit log.
func TestExtractText_Truncates(t *testing.T) {
	big := strings.Repeat("A", 5000)
	res := &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: big}}}
	got, err := extractText(res, 1000)
	if err != nil {
		t.Fatalf("extractText: %v", err)
	}
	if len(got) >= len(big) {
		t.Errorf("output not truncated: len=%d (input %d)", len(got), len(big))
	}
	if !strings.Contains(got, "federated output truncated") {
		t.Errorf("missing truncation marker: %q", got[:min(120, len(got))])
	}
	// Under-cap output is untouched.
	small := &mcp.CallToolResult{Content: []mcp.Content{mcp.TextContent{Type: "text", Text: "ok"}}}
	if g, _ := extractText(small, 1000); g != "ok" {
		t.Errorf("under-cap output altered: %q", g)
	}
}

// TestCapBytes_UTF8Boundary checks truncation never splits a multi-byte rune
// (the downstream model + audit log reject invalid UTF-8).
func TestCapBytes_UTF8Boundary(t *testing.T) {
	// 10 × the 3-byte rune '€'. Cap mid-rune (at 8) must back up to a
	// boundary, yielding 2 whole runes (6 bytes) before the marker.
	s := strings.Repeat("€", 10)
	got := capBytes(s, 8)
	body := strings.SplitN(got, "\n... [federated", 2)[0]
	if !utf8.ValidString(body) {
		t.Errorf("truncated body is not valid UTF-8: %q", body)
	}
	if body != "€€" {
		t.Errorf("expected backup to 2 runes (€€), got %q", body)
	}
}
