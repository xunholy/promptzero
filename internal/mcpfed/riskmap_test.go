package mcpfed

import (
	"testing"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/xunholy/promptzero/internal/risk"
)

func boolPtr(b bool) *bool { return &b }

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		ann  mcp.ToolAnnotation
		def  risk.Level
		want risk.Level
	}{
		{"destructive wins", mcp.ToolAnnotation{DestructiveHint: boolPtr(true), ReadOnlyHint: boolPtr(true)}, risk.Low, risk.Critical},
		// Security floor: a server-supplied read-only hint must NOT drop a
		// federated tool below the operator's configured floor. With the
		// default High floor it stays High, not Low.
		{"readonly held at default floor (High)", mcp.ToolAnnotation{ReadOnlyHint: boolPtr(true)}, risk.High, risk.High},
		{"readonly held at default floor (Medium)", mcp.ToolAnnotation{ReadOnlyHint: boolPtr(true)}, risk.Medium, risk.Medium},
		// The attack: a destructive remote tool marked read-only to slip past
		// the gates. DestructiveHint precedence keeps it Critical; even
		// without it, the read-only hint can no longer reach Low.
		{"destructive+readonly stays critical", mcp.ToolAnnotation{DestructiveHint: boolPtr(true), ReadOnlyHint: boolPtr(true)}, risk.High, risk.Critical},
		// Only when the operator explicitly lowers RiskDefault does a
		// read-only tool reach Low — their informed choice.
		{"readonly reaches Low only via operator default", mcp.ToolAnnotation{ReadOnlyHint: boolPtr(true)}, risk.Low, risk.Low},
		{"openworld bumps default", mcp.ToolAnnotation{OpenWorldHint: boolPtr(true)}, risk.Medium, risk.High},
		{"openworld caps at critical", mcp.ToolAnnotation{OpenWorldHint: boolPtr(true)}, risk.Critical, risk.Critical},
		{"no hints uses default", mcp.ToolAnnotation{}, risk.Medium, risk.Medium},
		{"explicit destructive false ignored", mcp.ToolAnnotation{DestructiveHint: boolPtr(false)}, risk.High, risk.High},
		{"explicit readonly false falls through", mcp.ToolAnnotation{ReadOnlyHint: boolPtr(false)}, risk.Medium, risk.Medium},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classify(mcp.Tool{Annotations: tc.ann}, tc.def)
			if got != tc.want {
				t.Errorf("classify(%v, %v) = %v, want %v", tc.ann, tc.def, got, tc.want)
			}
		})
	}
}

func TestParseDefaultRisk(t *testing.T) {
	cases := map[string]risk.Level{
		"":          risk.High,
		"low":       risk.Low,
		"Medium":    risk.Medium,
		"HIGH":      risk.High,
		"critical":  risk.Critical,
		"   high  ": risk.High,
		"unknown":   risk.High, // safe fallback
	}
	for in, want := range cases {
		if got := parseDefaultRisk(in); got != want {
			t.Errorf("parseDefaultRisk(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestBumpOne(t *testing.T) {
	if got := bumpOne(risk.Low); got != risk.Medium {
		t.Errorf("Low+1 = %v, want Medium", got)
	}
	if got := bumpOne(risk.Medium); got != risk.High {
		t.Errorf("Medium+1 = %v, want High", got)
	}
	if got := bumpOne(risk.High); got != risk.Critical {
		t.Errorf("High+1 = %v, want Critical", got)
	}
	if got := bumpOne(risk.Critical); got != risk.Critical {
		t.Errorf("Critical+1 = %v, want Critical (cap)", got)
	}
}
