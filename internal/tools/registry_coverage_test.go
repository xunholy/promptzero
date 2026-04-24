package tools_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/xunholy/promptzero/internal/risk"
)

// TestRegistryCoverage pins the contract for every Spec in the production
// registry. It uses initialSpecs (captured in TestMain before any
// resetForTest() call can clear the registry) so test-ordering doesn't
// affect coverage results.
//
// Invariants checked per Spec:
//   - Description must be non-empty.
//   - Schema must be valid JSON.
//   - Handler must be non-nil.
//   - Spec.Risk must match risk.Classify(spec.Name) so the MCP annotation
//     hints and the agent confirmation gate stay aligned.
//
// Future drift is caught at CI time: adding a tool with a mismatched risk
// level will fail this test.
func TestRegistryCoverage(t *testing.T) {
	if len(initialSpecs) == 0 {
		t.Fatal("initialSpecs is empty — TestMain didn't run or init() funcs not linked")
	}

	for _, spec := range initialSpecs {
		spec := spec
		t.Run(spec.Name, func(t *testing.T) {
			// 1. Description must not be empty.
			if spec.Description == "" {
				t.Errorf("spec %q has empty Description", spec.Name)
			}

			// 2. Schema must be valid JSON.
			if len(spec.Schema) == 0 {
				t.Errorf("spec %q has nil/empty Schema", spec.Name)
			} else {
				var top map[string]json.RawMessage
				if err := json.Unmarshal(spec.Schema, &top); err != nil {
					t.Errorf("spec %q Schema is not valid JSON: %v", spec.Name, err)
				}
			}

			// 3. Handler must be non-nil.
			if spec.Handler == nil {
				t.Errorf("spec %q has nil Handler", spec.Name)
			}

			// 4. Spec.Risk must match risk.Classify for the canonical name.
			//    ClassifyExplicit distinguishes explicit classification from
			//    the "fall through to High" default; tools that rely on the
			//    default MUST have Risk == risk.High in their Spec so there is
			//    no ambiguity between "intentionally High" and "forgot to add
			//    to risk.go".
			want := risk.Classify(spec.Name)
			if spec.Risk != want {
				t.Errorf("spec %q Risk = %s, but risk.Classify returns %s — update spec.Risk or risk.go",
					spec.Name, riskString(spec.Risk), riskString(want))
			}
		})
	}
}

// riskString returns the Level's string representation for use in test
// messages without importing the unexported stringer directly.
func riskString(l risk.Level) string {
	return fmt.Sprintf("%v", l)
}
