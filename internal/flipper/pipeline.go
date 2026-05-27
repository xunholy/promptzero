package flipper

import (
	"strings"
	"time"

	"github.com/xunholy/promptzero/internal/obs"
)

// PipelineProfile names a bundled retry/timeout policy applied across the
// command-dispatch layer (CLI exec, file write, RPC handshake, reconnect).
// Profiles let operators trade latency for reliability without re-deriving
// every constant by hand: a flaky USB cable picks "resilient", a known-good
// dev rig picks "fast", and the default ("balanced") matches the historical
// hard-coded behaviour byte-for-byte so existing scripts and tests keep
// their timing.
//
// Inspired by V3SP3R's CommandPipelineAutotuneStatus shape — but the
// auto-tune feedback loop is intentionally NOT implemented here; profile
// selection is manual in this round. The struct is deliberately a flat
// bundle of durations so the future telemetry-driven auto-tuner can swap
// it atomically via SetPipeline without redoing the wire path.
type PipelineProfile string

const (
	// ProfileFast favours snappy failure over robustness. Suitable for
	// known-good USB rigs running CI or interactive dev where a hung
	// command should fall through fast and surface as an error rather
	// than waste seconds retrying.
	ProfileFast PipelineProfile = "fast"

	// ProfileBalanced is the default. Every value matches the legacy
	// hard-coded constants from before the pipeline refactor:
	//   - rpc.Open: 5 attempts, 500ms per ping
	//   - ExecCtx: 10s
	//   - WriteFileCtx: 10s
	//   - reconnect inter-attempt sleep: 250ms
	// Anything depending on the previous timing characteristics
	// (existing tests, scripts, hand-tuned configs) must observe
	// identical behaviour under this profile.
	ProfileBalanced PipelineProfile = "balanced"

	// ProfileResilient stretches every retry budget so commands ride
	// through transient cable wobble, BLE link drops, or a busy
	// firmware. Pays for it with latency on the failure path.
	ProfileResilient PipelineProfile = "resilient"
)

// Pipeline carries the resolved retry and timeout knobs for one profile.
// Zero values are not valid; always construct via ProfileSettings (or copy
// from one and tweak fields explicitly) so missing fields don't silently
// degrade to no-retry/no-timeout behaviour. Pipeline values are immutable
// after construction — *Flipper holds them by atomic.Pointer so a live
// SetPipeline call can swap the whole bundle without partial reads.
type Pipeline struct {
	// CLIRetryAttempts is the number of times ExecCtx will issue the
	// command before giving up. Each attempt is gated by the per-command
	// Exec timeout. Only transient errors (command hung, send failures)
	// trigger a retry; non-transient errors (context cancelled, bridge
	// mode, unknown command) return immediately. Value of 1 (or <=0)
	// means single-shot (no retries).
	CLIRetryAttempts int
	// CLIRetryDelay is the delay between CLI retries when CLIRetryAttempts > 1.
	CLIRetryDelay time.Duration

	// RPCRetryAttempts is the number of Ping attempts rpc.Client.Open
	// will make before giving up. The legacy value was 5.
	RPCRetryAttempts int
	// RPCRetryDelay is the per-attempt context timeout used by Open's
	// Ping. The legacy value was 500ms.
	RPCRetryDelay time.Duration

	// FileWriteRetryAttempts is the number of times WriteFileCtx will
	// re-issue a failed storage write_chunk before giving up. As with
	// CLIRetryAttempts, today's WriteFileCtx is single-shot; values > 1
	// are reserved for the auto-tune follow-up.
	FileWriteRetryAttempts int
	// FileWriteRetryDelay is the delay between file-write retries.
	FileWriteRetryDelay time.Duration

	// Exec is the per-command read deadline used by ExecCtx. Replaces
	// the previous f.execTimeout SetExecTimeout setter as the source of
	// truth.
	Exec time.Duration
	// WriteFile is the post-payload read deadline used by WriteFileCtx.
	WriteFile time.Duration
	// Connect is the budget for the connect/reconnect cycle. ConnectURL
	// uses the caller-supplied timeout argument directly today; this
	// value is consulted by reconnectIfNeededLocked when the original
	// connectTimeout wasn't recorded.
	Connect time.Duration

	// ReconnectAttemptDelay is the inner sleep between transport
	// reconnect attempts in reconnectIfNeededLocked. Legacy value was
	// 250ms.
	ReconnectAttemptDelay time.Duration
}

// ProfileSettings returns the canonical Pipeline bundle for the named
// profile. An unknown or empty name returns the Balanced bundle so a
// stale config string can never zero out the timeouts.
func ProfileSettings(p PipelineProfile) Pipeline {
	switch normalizeProfileName(p) {
	case ProfileFast:
		return Pipeline{
			CLIRetryAttempts:       1,
			CLIRetryDelay:          100 * time.Millisecond,
			RPCRetryAttempts:       3,
			RPCRetryDelay:          250 * time.Millisecond,
			FileWriteRetryAttempts: 1,
			FileWriteRetryDelay:    100 * time.Millisecond,
			Exec:                   5 * time.Second,
			WriteFile:              5 * time.Second,
			Connect:                5 * time.Second,
			ReconnectAttemptDelay:  150 * time.Millisecond,
		}
	case ProfileResilient:
		return Pipeline{
			CLIRetryAttempts:       3,
			CLIRetryDelay:          750 * time.Millisecond,
			RPCRetryAttempts:       10,
			RPCRetryDelay:          1 * time.Second,
			FileWriteRetryAttempts: 3,
			FileWriteRetryDelay:    750 * time.Millisecond,
			Exec:                   30 * time.Second,
			WriteFile:              30 * time.Second,
			Connect:                30 * time.Second,
			ReconnectAttemptDelay:  500 * time.Millisecond,
		}
	default:
		// Balanced — every value here MUST equal the legacy hard-coded
		// constant from the matching call site so behaviour with
		// pipeline=balanced is byte-for-byte identical to the
		// pre-pipeline build. Verified against:
		//   serial.go ExecCtx execTO default       -> 10 * time.Second
		//   serial.go WriteFileCtx writeTO default -> 10 * time.Second
		//   rpc/client.go Open attempt cap         -> 5
		//   rpc/client.go Open ping ctx timeout    -> 500 * time.Millisecond
		//   serial.go reconnectIfNeededLocked sleep-> 250 * time.Millisecond
		//   cmd/promptzero/setup.go --connect-timeout default -> 10 * time.Second
		return Pipeline{
			CLIRetryAttempts:       1,
			CLIRetryDelay:          250 * time.Millisecond,
			RPCRetryAttempts:       5,
			RPCRetryDelay:          500 * time.Millisecond,
			FileWriteRetryAttempts: 1,
			FileWriteRetryDelay:    250 * time.Millisecond,
			Exec:                   10 * time.Second,
			WriteFile:              10 * time.Second,
			Connect:                10 * time.Second,
			ReconnectAttemptDelay:  250 * time.Millisecond,
		}
	}
}

// normalizeProfileName lowercases and trims s so config strings like
// "Balanced", "  resilient ", or "FAST" all resolve. Unknown values
// fall through to the default branch in ProfileSettings.
func normalizeProfileName(p PipelineProfile) PipelineProfile {
	return PipelineProfile(strings.ToLower(strings.TrimSpace(string(p))))
}

// SetPipeline swaps the active profile bundle on f. The swap is atomic
// (atomic.Pointer) so an in-flight ExecCtx that read the old pipeline
// reference completes against the old values; the next ExecCtx sees the
// new bundle. Empty / unknown names resolve to ProfileBalanced via
// ProfileSettings.
func (f *Flipper) SetPipeline(p PipelineProfile) {
	bundle := ProfileSettings(p)
	f.pipelineCfg.Store(&bundle)
}

// SetPipelineBundle is a Pipeline-typed counterpart to SetPipeline used
// by callers (and tests) that have already resolved a Pipeline by hand
// — e.g. tests asserting a specific timeout, or a future auto-tuner
// emitting bundles that don't correspond to one of the three named
// profiles. A zero-valued Pipeline is rejected with a warn log (every
// timeout would be 0, so ExecCtx / WriteFileCtx would fire
// context.DeadlineExceeded immediately on every call); pass
// ProfileSettings(ProfileBalanced) to reset.
//
// The reject path was promised by the docstring but pre-this-fix not
// enforced — a caller passing `Pipeline{}` silently wedged the agent's
// CLI dispatch on the next command.
func (f *Flipper) SetPipelineBundle(p Pipeline) {
	if isZeroPipeline(p) {
		obs.Default().Warn("flipper_set_pipeline_bundle_rejected_zero",
			"reason", "all timeouts zero — every CLI dispatch would expire immediately. "+
				"Pass ProfileSettings(ProfileBalanced) to reset.")
		return
	}
	bundle := p
	f.pipelineCfg.Store(&bundle)
}

// isZeroPipeline reports whether p is the zero value (every timeout
// 0). Used by SetPipelineBundle to honour the docstring's rejection
// promise. We check the load-bearing timeout fields (Exec, WriteFile,
// Connect) rather than every field — a future Pipeline addition with
// a meaningful zero default shouldn't false-positive here.
func isZeroPipeline(p Pipeline) bool {
	return p.Exec == 0 && p.WriteFile == 0 && p.Connect == 0
}

// pipeline returns the current resolved Pipeline. When no profile has
// been set yet the Balanced bundle is returned so first-call dispatch
// gets the legacy values without an extra branch in the hot path.
func (f *Flipper) pipeline() Pipeline {
	if p := f.pipelineCfg.Load(); p != nil {
		return *p
	}
	return ProfileSettings(ProfileBalanced)
}
