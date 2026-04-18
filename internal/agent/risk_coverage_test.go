package agent

import (
	"sort"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// TestRiskCoverage enforces that every tool registered with the agent has an
// explicit risk classification in internal/risk/risk.go. When a new tool
// lands in one of the builder functions but the reviewer forgets to add a
// corresponding entry to risk.toolLevels, the tool silently defaults to
// High — which is safe, but also masks the mistake. This test fails loudly
// so the omission is caught in CI.
func TestRiskCoverage(t *testing.T) {
	var missing []string
	for _, name := range ToolNames(true) {
		if _, ok := risk.ClassifyExplicit(name); !ok {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("the following tools have no explicit risk classification in internal/risk/risk.go — add them to toolLevels:\n  - %s",
			joinLines(missing))
	}
}

func joinLines(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += "\n  - "
		}
		out += n
	}
	return out
}
