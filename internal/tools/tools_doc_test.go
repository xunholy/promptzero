// SPDX-License-Identifier: AGPL-3.0-or-later

package tools

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// TestToolsDocHeadingsAreRegistered guards docs/reference/tools.md — the
// canonical tool catalog — against drift: every per-tool entry heading
// ("### `name` · risk") must be a tool's CANONICAL registered name, not
// a legacy alias and not a name that no longer exists. Requiring the
// canonical name (Get returns the Spec; its Name must equal the heading)
// catches the case this test was written for — device_info had been
// documented only under its legacy alias system_info, so an operator
// looking up the canonical name the registry surfaces found no entry —
// as well as a heading for a tool that was removed or renamed.
func TestToolsDocHeadingsAreRegistered(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "reference", "tools.md"))
	if err != nil {
		t.Fatalf("read tools.md: %v", err)
	}
	// The per-tool entry headings: "### `tool_name` · tier" (the middle
	// dot precedes the risk tier). We capture both the name and the tier
	// so a single pass can validate each. A format change that breaks the
	// match fails this loudly, which is the intended prompt to update the
	// matcher.
	re := regexp.MustCompile("(?m)^### `([a-z][a-z0-9_]+)` · ([a-z]+)")
	matches := re.FindAllSubmatch(data, -1)
	if len(matches) == 0 {
		t.Fatal("no tool-entry headings found in tools.md — heading format changed?")
	}
	for _, m := range matches {
		name := string(m[1])
		docTier := string(m[2])
		spec, ok := Get(name)
		if !ok {
			t.Errorf("tools.md documents %q but no tool/alias is registered under that name", name)
			continue
		}
		if spec.Name != name {
			t.Errorf("tools.md heading %q is a legacy alias of %q — use the canonical name in the reference catalog", name, spec.Name)
		}
		// The tier printed in the heading must equal the tier the code
		// actually enforces via risk.Classify. This closes the drift class
		// that previously required manual re-syncing (PRs #211/#212): a
		// doc that over- or under-states a tool's gate now fails the build
		// instead of silently misleading an operator.
		if want := risk.Classify(name).String(); docTier != want {
			t.Errorf("tools.md heading for %q says risk %q but risk.Classify enforces %q — update the doc tier to match the code", name, docTier, want)
		}
	}
}
