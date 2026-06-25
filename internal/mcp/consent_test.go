// SPDX-License-Identifier: AGPL-3.0-or-later

package mcp

import (
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// TestConsentDecision exercises the full MCP risk-consent matrix: every
// risk tier against every combination of the two opt-in flags. The gate
// is a crown-jewel safety rail, so the table is exhaustive — in particular
// it pins the one-directional implication (ALLOW_CRITICAL permits High, but
// ALLOW_HIGH must NOT unlock Critical) and that Low/Medium are never gated.
func TestConsentDecision(t *testing.T) {
	cases := []struct {
		name          string
		level         risk.Level
		allowHigh     bool
		allowCritical bool
		wantAllowed   bool
		wantMsg       string
	}{
		// Low / Medium are never gated, regardless of flags.
		{"low default", risk.Low, false, false, true, ""},
		{"low even with no flags", risk.Low, false, false, true, ""},
		{"medium default", risk.Medium, false, false, true, ""},
		{"medium with high flag", risk.Medium, true, false, true, ""},

		// High tier.
		{"high default denied", risk.High, false, false, false, consentDenyHigh},
		{"high allowed by high flag", risk.High, true, false, true, ""},
		{"high allowed by critical flag (implication)", risk.High, false, true, true, ""},
		{"high allowed by both", risk.High, true, true, true, ""},

		// Critical tier.
		{"critical default denied", risk.Critical, false, false, false, consentDenyCritical},
		// The gap this test exists to close: ALLOW_HIGH must NOT unlock Critical.
		{"critical NOT unlocked by high flag", risk.Critical, true, false, false, consentDenyCritical},
		{"critical allowed by critical flag", risk.Critical, false, true, true, ""},
		{"critical allowed by both", risk.Critical, true, true, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			allowed, msg := consentDecision(c.level, c.allowHigh, c.allowCritical)
			if allowed != c.wantAllowed {
				t.Errorf("allowed = %v, want %v", allowed, c.wantAllowed)
			}
			if msg != c.wantMsg {
				t.Errorf("denyMsg = %q, want %q", msg, c.wantMsg)
			}
		})
	}
}
