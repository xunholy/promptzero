// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// TestRiskFloor_ActiveDangerousToolsAreHighOrAbove is a safety guardrail.
// Every tool whose name ends in an "active" high-blast-radius suffix — one
// that transmits RF, emulates a credential/tag, deauthenticates, jams, spams,
// floods, injects onto a bus, replays, or brute-forces over the air — must be
// classified risk.High or risk.Critical. That tier guarantees the operation
// can never be auto-approved, is always confirm-gated and audit-gated, and is
// refused in read-only mode.
//
// Unknown tools already default to High (risk.Classify's safe default), so the
// only way to under-tier an active tool is an explicit entry in risk.go's Low
// or Medium lists. This test catches exactly that mistake the moment a new
// active tool is added or an existing one is downgraded — a class of error
// that would otherwise silently open a gate bypass for the most consequential
// operations PromptZero can perform.
func TestRiskFloor_ActiveDangerousToolsAreHighOrAbove(t *testing.T) {
	// Suffixes that denote the *active* form of the operation. Detection /
	// analysis variants (e.g. "..._detect", "..._jammer_detect") do not end
	// in these, so they are not matched.
	activeSuffixes := []string{
		"_transmit", "_tx", "_deauth", "_emulate", "_jam",
		"_spam", "_replay", "_bruteforce", "_inject", "_flood",
	}

	// Passive exceptions: these END in an active suffix but are RX-only
	// monitors that transmit nothing, so Medium (the tier shared by other
	// passive radio activations like subghz_receive / wifi_scan_ap) is
	// correct. Keep this list minimal and justified — a new entry here is a
	// claim that the tool genuinely performs no active emission.
	passiveException := map[string]string{
		"wifi_sniff_deauth": "sniffs deauth frames passively; transmits nothing",
	}

	for _, s := range All() {
		matched := ""
		for _, suf := range activeSuffixes {
			if strings.HasSuffix(s.Name, suf) {
				matched = suf
				break
			}
		}
		if matched == "" {
			continue
		}
		if _, ok := passiveException[s.Name]; ok {
			continue
		}
		if s.Risk < risk.High {
			t.Errorf("active tool %q (suffix %q) is classified %s; tools that actively transmit / "+
				"emulate / deauth / jam / spam / flood / inject / replay / brute-force MUST be High or "+
				"Critical so they are confirm-gated, audit-gated, and refused in read-only mode",
				s.Name, matched, s.Risk)
		}
	}
}
