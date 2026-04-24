package mcpfed

import (
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/xunholy/promptzero/internal/risk"
)

// classify maps an MCP tool's annotations to a PromptZero risk level. The
// mapping is conservative — federated tools lacking explicit annotations
// fall back to the per-server default (or High if that is also unset).
//
// Rules (highest precedence first):
//
//  1. DestructiveHint=true               → Critical
//  2. ReadOnlyHint=true                  → Low
//  3. OpenWorldHint=true (else)          → bumped one tier above baseline,
//                                          capped at Critical
//  4. (no annotations / all nil)         → defaultLevel
//
// IdempotentHint is descriptive only; it does not influence the risk tier
// because PromptZero's gate considers blast radius, not retry-safety.
func classify(t mcp.Tool, defaultLevel risk.Level) risk.Level {
	a := t.Annotations

	if a.DestructiveHint != nil && *a.DestructiveHint {
		return risk.Critical
	}
	if a.ReadOnlyHint != nil && *a.ReadOnlyHint {
		return risk.Low
	}

	base := defaultLevel
	if a.OpenWorldHint != nil && *a.OpenWorldHint {
		base = bumpOne(base)
	}
	return base
}

// bumpOne returns the next-higher risk tier, capped at Critical.
func bumpOne(l risk.Level) risk.Level {
	switch l {
	case risk.Low:
		return risk.Medium
	case risk.Medium:
		return risk.High
	case risk.High, risk.Critical:
		return risk.Critical
	default:
		return risk.High
	}
}

// parseDefaultRisk converts a config string to a risk level. Empty input
// returns High — the safest fallback for unclassified federated tools.
func parseDefaultRisk(s string) risk.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "low":
		return risk.Low
	case "medium":
		return risk.Medium
	case "critical":
		return risk.Critical
	case "high", "":
		return risk.High
	default:
		return risk.High
	}
}
