package agent

import (
	"context"
	"fmt"
)

// Batch C — verify-everywhere. Extends the chain-of-verification pass
// (previously only applied to generate_* LLM payloads) to the
// parametric file builders (subghz_build / rfid_build / ir_build /
// nfc_build). Go-side builders already validate structure, but the
// Haiku verifier still catches the semantic gotchas that bit-level
// validation misses — frequency/preset mismatches, UID-length vs
// declared DeviceType drift, raw-signal stubs below the 4-sample
// floor, etc.
//
// The helper below is intentionally small: the caller already has the
// built bytes in hand, so all it asks is "was that OK to write?" and
// gets back either a verdict summary line to append on success, or a
// blocking error message (when severity is high/critical and the
// caller did not opt into bypass). Builders plug the summary into
// their normal success string and return the error verbatim on block.

// runBuildVerification calls the registered verifier (or the production
// one when none is installed) on freshly-built file bytes, returning
// whichever of (summary, blockMsg) is non-empty. A non-empty blockMsg
// means the caller must NOT persist the file; they should surface the
// message back to the model as the tool result. An empty blockMsg +
// non-empty summary means the write can proceed and the summary should
// be appended to the success message.
//
// Concurrency contract: caller MUST hold a.mu, matching verifyPayload.
func (a *Agent) runBuildVerification(ctx context.Context, payloadType string, content []byte, bypass bool) (summary, blockMsg string) {
	fn := a.verifierFn
	if fn == nil {
		fn = a.verifyPayload
	}
	verdict, _ := fn(ctx, payloadType, string(content))
	summary = verdictSummary(verdict)
	if shouldBlockDeploy(verdict, bypass) {
		blockMsg = fmt.Sprintf("build blocked by verifier.\n\n%s\n\nPass verify_bypass=true to override if you accept the risk.", summary)
	}
	return summary, blockMsg
}
