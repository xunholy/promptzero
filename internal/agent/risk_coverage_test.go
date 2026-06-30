package agent

import (
	"fmt"
	"sort"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
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

// TestRiskClassificationMatchesSpec enforces that every tool's static
// classification (risk.Classify, backed by the hand-maintained toolLevels map)
// equals its registry Spec.Risk. The agent Run loop gates on risk.Classify
// alone, while RunTool and the MCP server gate on Spec.Risk (max Classify); they
// agree for all tools today, and that agreement is precisely what makes the Run
// loop's Classify-only resolution safe. If the two ever diverge — e.g. a tool
// registered Critical but mapped Medium in toolLevels — a destructive tool could
// be under-gated on the Run-loop path while RunTool/MCP gate it correctly.
// TestRiskCoverage only checks that a classification exists; this checks the
// value matches. Fail loudly so the mismatch is fixed at the source.
func TestRiskClassificationMatchesSpec(t *testing.T) {
	var mismatch []string
	for _, name := range ToolNames(true) {
		spec, ok := toolsreg.Get(name)
		if !ok {
			continue
		}
		if c := risk.Classify(name); c != spec.Risk {
			mismatch = append(mismatch, fmt.Sprintf("%s: spec.Risk=%s classify=%s", name, spec.Risk, c))
		}
	}
	if len(mismatch) > 0 {
		sort.Strings(mismatch)
		t.Fatalf("tool risk classification (risk.toolLevels) disagrees with registry Spec.Risk — the Run-loop and RunTool/MCP gates would diverge:\n  - %s",
			joinLines(mismatch))
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
