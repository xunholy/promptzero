package workflows

import (
	"fmt"
	"runtime/debug"
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/obs"
)

// runPhase times a sub-step, captures its output, and returns a structured
// PhaseResult. phaseName is the logical step identifier ("detect", "dump",
// "suggest"); tool is the primitive name as it would appear in the audit
// log (e.g. "nfc_detect"). The inner fn is the primitive call itself.
//
// Errors are folded into the OK flag and their message is stored in
// Output so the LLM can reason over the failure text without a separate
// error field in the JSON envelope. Callers decide whether to bail or
// continue based on p.OK.
func runPhase(phaseName, tool string, fn func() (string, error)) (p PhaseResult) {
	start := time.Now()
	p = PhaseResult{Phase: phaseName, Tool: tool}
	// Recover panics inside the phase fn so a buggy workflow
	// step (nil-deref on an unexpected device-state shape, parse
	// failure on an attacker-controllable response) produces a
	// failed phase rather than crashing the whole agent. Mirrors
	// the dispatch-level recover added in c9f7cb3.
	defer func() {
		p.ElapsedMs = time.Since(start).Milliseconds()
		if r := recover(); r != nil {
			obs.Default().Error("workflow_phase_panicked",
				"phase", phaseName,
				"tool", tool,
				"recovered", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
			p.OK = false
			p.Output = fmt.Sprintf("phase %s panicked: %v", phaseName, r)
		}
	}()

	out, err := fn()
	if err != nil {
		p.OK = false
		p.Output = strings.TrimSpace(out + "\n" + err.Error())
		return p
	}
	p.OK = true
	p.Output = strings.TrimSpace(out)
	return p
}

// internalPhase builds a synthetic phase result for decisions made by the
// workflow itself (e.g. "analysed detection output and selected next
// attack"). Used to keep the phases[] array self-describing when a
// workflow's reasoning step isn't backed by a primitive call.
func internalPhase(phaseName, output string) PhaseResult {
	return PhaseResult{
		Phase:     phaseName,
		Tool:      "_internal",
		Output:    output,
		OK:        true,
		ElapsedMs: 0,
	}
}
