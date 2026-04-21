package agent

import (
	"encoding/json"
	"strings"

	"github.com/xunholy/promptzero/internal/rules"
)

// appendDetectorVerdicts renders a set of detector Verdicts into the
// tool output as a <detector-verdict> block per verdict. Runs after
// the reflexion hook but before quarantine wrapping so the detector
// signals ride inside the same <untrusted-hardware-output> envelope
// as the raw tool output — they're not user-controllable but they
// are model-generated, and keeping them inside the envelope preserves
// a clean "this whole block is tool-generated" boundary.
//
// A suspicious or failure verdict gets a leading sentinel the model
// is most likely to attend to; success and unknown verdicts are
// rendered in order without highlighting.
func appendDetectorVerdicts(output string, verdicts []rules.Verdict) string {
	if len(verdicts) == 0 {
		return output
	}
	var b strings.Builder
	b.WriteString(output)
	for _, v := range verdicts {
		body, err := json.Marshal(v)
		if err != nil {
			continue
		}
		b.WriteString("\n\n<detector-verdict>")
		b.Write(body)
		b.WriteString("</detector-verdict>")
	}
	return b.String()
}
