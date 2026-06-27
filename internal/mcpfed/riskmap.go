package mcpfed

import (
	"strings"

	"github.com/mark3labs/mcp-go/mcp"

	"github.com/xunholy/promptzero/internal/risk"
)

// classify maps an MCP tool's annotations to a PromptZero risk level. The
// annotations come from the *untrusted federated server*, so the security
// invariant is: a hint may only RAISE risk, never lower it below the
// operator's configured floor (defaultLevel, defaulting to High). Otherwise
// a malicious or compromised server could mark a destructive tool read-only
// to drop to Low and bypass the confirm / audit / read-only-mode gates —
// defeating the "every federated tool is at least the operator's default"
// guarantee those gates rely on.
//
// Rules (highest precedence first):
//
//  1. DestructiveHint=true   → Critical (raise to max; cautious even if the
//     server also sets ReadOnlyHint, i.e. contradicts itself).
//  2. ReadOnlyHint=true      → defaultLevel (the operator's floor). The hint
//     is honoured only as "no escalation needed", never as a reduction below
//     the floor. An operator who trusts a server lowers its RiskDefault.
//  3. OpenWorldHint=true (else) → bumped one tier above the floor, capped at
//     Critical.
//  4. (no annotations / all nil) → defaultLevel.
//
// IdempotentHint is descriptive only; it does not influence the risk tier
// because PromptZero's gate considers blast radius, not retry-safety.
func classify(t mcp.Tool, defaultLevel risk.Level) risk.Level {
	a := t.Annotations

	if a.DestructiveHint != nil && *a.DestructiveHint {
		return risk.Critical
	}
	if a.ReadOnlyHint != nil && *a.ReadOnlyHint {
		// Never below the operator's floor — see the invariant above. A
		// server-supplied read-only hint cannot drop a federated tool to Low
		// and slip past the gates.
		return defaultLevel
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
