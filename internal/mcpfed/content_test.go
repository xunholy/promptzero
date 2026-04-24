package mcpfed

import (
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestExtractText_TextContent(t *testing.T) {
	res := &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{Text: "hello"},
			mcp.TextContent{Text: "world"},
		},
	}
	got, err := extractText(res)
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
	got, err := extractText(res)
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
	_, err := extractText(res)
	if err == nil {
		t.Fatalf("expected error for IsError=true")
	}
	if !strings.Contains(err.Error(), "bad input") {
		t.Errorf("error did not include body: %v", err)
	}
}

func TestExtractText_Nil(t *testing.T) {
	_, err := extractText(nil)
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
	got, err := extractText(res)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "[image: image/png") {
		t.Errorf("image placeholder missing from %q", got)
	}
}
