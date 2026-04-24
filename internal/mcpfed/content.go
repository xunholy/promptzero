package mcpfed

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
)

// extractText flattens an MCP CallToolResult into a single string suitable
// for return from a tools.Handler. The dispatch path treats the string as
// the tool's textual output and an error separately.
//
// Strategy:
//
//  1. If the server returned StructuredContent, render it as compact JSON.
//     This is the preferred surface for tool outputs that fit a schema —
//     e.g. nmap host lists, hashcat recovered keys.
//  2. Otherwise, concatenate every TextContent part with newline separators.
//  3. Image / audio / embedded-resource parts are summarised as a one-line
//     placeholder ("[image: PNG; 4321 bytes]") because the agent's
//     downstream model cannot consume binary directly.
//
// IsError on the result becomes a returned error — "error" is the right
// signal because the agent's risk + reflexion paths inspect err for retry
// vs. abort decisions.
func extractText(res *mcp.CallToolResult) (string, error) {
	if res == nil {
		return "", fmt.Errorf("mcpfed: nil CallToolResult")
	}

	body := renderBody(res)

	if res.IsError {
		// Surface the rendered body in the error message itself —
		// callers (audit log, the agent's reflexion path) want it
		// inline, not buried in a separate field.
		if body == "" {
			return "", fmt.Errorf("mcpfed: tool returned isError=true with empty body")
		}
		return "", fmt.Errorf("mcpfed: tool error: %s", body)
	}

	return body, nil
}

func renderBody(res *mcp.CallToolResult) string {
	if res.StructuredContent != nil {
		// Marshal-then-fail-soft: if the server gave us something
		// JSON can't represent, fall through to text rendering.
		if b, err := json.Marshal(res.StructuredContent); err == nil {
			return string(b)
		}
	}

	var sb strings.Builder
	for i, c := range res.Content {
		if i > 0 {
			sb.WriteByte('\n')
		}
		switch v := c.(type) {
		case mcp.TextContent:
			sb.WriteString(v.Text)
		case mcp.ImageContent:
			fmt.Fprintf(&sb, "[image: %s; %d bytes base64]", v.MIMEType, len(v.Data))
		case mcp.AudioContent:
			fmt.Fprintf(&sb, "[audio: %s; %d bytes base64]", v.MIMEType, len(v.Data))
		case mcp.EmbeddedResource:
			fmt.Fprintf(&sb, "[resource: %T]", v.Resource)
		default:
			// Unknown content type — render as JSON so the agent
			// at least sees the shape.
			if b, err := json.Marshal(v); err == nil {
				sb.Write(b)
			} else {
				fmt.Fprintf(&sb, "[unrenderable content of type %T]", v)
			}
		}
	}
	return sb.String()
}
