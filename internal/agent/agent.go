package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/breaker"
	"github.com/xunholy/promptzero/internal/bruce"
	"github.com/xunholy/promptzero/internal/buspirate"
	"github.com/xunholy/promptzero/internal/confidence"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/diff"
	"github.com/xunholy/promptzero/internal/faultier"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/mode"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/rag"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/session"
	"github.com/xunholy/promptzero/internal/snapshot"
	"github.com/xunholy/promptzero/internal/streaming"
	"github.com/xunholy/promptzero/internal/targetmem"
	toolsreg "github.com/xunholy/promptzero/internal/tools"
	"github.com/xunholy/promptzero/internal/vision"
)

// ErrBlockedByMode is the sentinel returned by dispatch when the
// active operation mode (Recon/Intel/Stealth/Assault) does not allow
// a tool's group. Callers (telemetry, UI) can errors.Is against this
// so the rejection is distinguishable from a runtime failure.
//
// Layered after ErrReadOnly: dispatch consults readOnly first; mode
// is checked only when readOnly=false. v0.19.0 introduced the
// read-only rail; mode was originally slated for removal in v0.20.0
// but remained as a useful coarse capability filter (see
// mode_dispatch_test.go).
var ErrBlockedByMode = errors.New("tool blocked by operation mode")

// ErrReadOnly is returned by dispatch when the agent is in read-only
// mode (SetReadOnly(true)) and the operator (or the LLM) attempts a
// tool whose risk classification is anything above risk.Low. Read-only
// is the v0.19.0 replacement for the persona+mode allow-list maze:
// one boolean, one rule — Spec.Risk == risk.Low passes, anything else
// is refused.
var ErrReadOnly = errors.New("tool blocked: read-only mode (no writes, no transmits, no execution)")

// ErrBudgetExceeded is returned at the top of Run() when the cost
// tracker's session USD cap has been crossed. The configured warn
// callback fires at 80% as a courtesy; this sentinel is the hard stop
// at 100%. Operators raise the cap with /budget set $X to clear the
// state. Wraps for errors.Is so REPL / web layers can render a
// dedicated message rather than a generic "claude API: …" line.
var ErrBudgetExceeded = errors.New("session refused: USD budget exhausted (use /budget set $X to extend)")

// maxHistory is the maximum number of messages retained in the conversation
// history. When exceeded, the first 2 entries (initial context) are kept and
// the oldest middle entries are dropped.
const maxHistory = 100

// defaultMaxToolCallsPerTurn caps how many tool_use blocks Run will honour
// inside a single user turn before injecting a synthetic "cap reached"
// tool_result and breaking out. Guards against runaway tool loops where a
// model keeps re-invoking tools without ever emitting a text-only reply.
// Tunable per-agent via SetMaxToolsPerTurn.
const defaultMaxToolCallsPerTurn = 32

// ToolEvent describes one tool invocation phase. Phase is "start" when
// execution begins (Duration/Output are zero) and "finish" when it completes.
type ToolEvent struct {
	Phase    string
	Name     string
	Input    json.RawMessage
	Duration time.Duration
	Output   string
	Err      bool
}

// TextDelta carries a single chunk of streamed assistant text. Tool calls
// are reported separately through SetToolStatusCallback.
type TextDelta struct {
	Text string
}

// ConfirmRequest describes a pending tool invocation the UI is asked to
// approve before the agent runs it.
type ConfirmRequest struct {
	Tool  string
	Input json.RawMessage
	Risk  risk.Level

	// Diff is an optional unified-diff preview of the file the tool is
	// about to write. Populated by the confirmation flow for
	// medium-risk file-write tools whose Spec advertises a non-nil
	// WriteIntent (see internal/tools.Spec.WriteIntent). Empty when
	// the tool isn't a file write, the flow couldn't fetch the
	// existing content, or the new content is identical to the old.
	// UIs render it as a `<pre>` / colored block above the action
	// buttons.
	Diff string
}

// Decision is the user's reply to a ConfirmRequest.
type Decision int

const (
	DecisionApprove    Decision = iota // run this one tool
	DecisionDeny                       // skip this tool, feed "user denied" back
	DecisionApproveAll                 // run this and every remaining tool in the current turn
	DecisionRevise                     // skip this tool; inject the operator's revision as a user turn so the model re-plans
)

// ConfirmResponse is what a confirm callback returns. Decision is the
// primary signal; Revision carries free-form text when Decision ==
// DecisionRevise — the model will see it as a fresh user turn telling
// it what to change about the pending tool call.
type ConfirmResponse struct {
	Decision Decision
	Revision string
}

// ConfirmFunc is the callback type used by SetConfirmCallback. Implementations
// must block until the user (or some other authority) returns a
// ConfirmResponse. Honouring ctx cancellation is recommended — a
// cancelled ctx should return {Decision: DecisionDeny} so the agent
// short-circuits cleanly.
type ConfirmFunc func(ctx context.Context, req ConfirmRequest) ConfirmResponse

type Agent struct {
	// turnMu serialises whole turns. Held for the full duration of
	// Run / RunTool. Distinct from mu so Run can release mu during
	// long-blocking idle periods (notably confirmWithIdleTimeout —
	// which can block for up to 5 minutes waiting for the operator)
	// without letting a concurrent Run race into the middle of a
	// partially-advanced history.
	turnMu sync.Mutex

	mu           sync.Mutex
	client       *anthropic.Client
	flipper      *flipper.Flipper
	marauder     *marauder.Marauder
	bruce        *bruce.Client
	faultier     *faultier.Client
	buspirate    *buspirate.Client
	cfg          *config.Config
	model        string
	history      []anthropic.MessageParam
	auditLog     *audit.Log
	generator    *generate.Generator
	vision       *vision.Analyzer
	genLLM       provider.Provider
	toolStatusCb func(ToolEvent)
	textDeltaCb  func(TextDelta)
	// toolStreamCb receives partial frames emitted by tools that
	// opted into streaming dispatch (Spec.Streams=true,
	// Spec.StreamHandler set). Operator-facing only — frames don't
	// affect the LLM-visible tool_result. See internal/streaming
	// + dispatchStreaming. Nil disables streaming dispatch entirely
	// (tools fall back to their non-streaming Handler).
	//
	// Returning false from the callback signals abort-early: dispatch
	// closes the sink's Aborted() channel and cancels the per-tool
	// context, prompting honouring producers (e.g. subghz_receive
	// once a candidate lands) to wrap up and return a partial result.
	// Returning true keeps streaming.
	toolStreamCb  func(streaming.Frame) bool
	usageCb       func(u Usage)
	streamErrCb   func(err error)
	retryNotifyCb func(RetryNotice) // v0.21.0: per-attempt retry observer for transient API errors
	// budgetCheckCb is consulted at the start of every Run() turn.
	// Non-nil return aborts the turn before any tokens are spent —
	// closes the v0.21.0 gap where the cost tracker emitted a 100%
	// notification but did nothing to actually stop further spend.
	// Production wiring lives in cmd/promptzero/setup.go (setupBudget).
	budgetCheckCb      func() error
	confirmCb          ConfirmFunc
	confirmThreshold   risk.Level
	confirmIdleTimeout time.Duration
	sessionStore       *session.Store
	sessionID          string
	persona            *persona.Persona
	personaAtomic      atomic.Pointer[persona.Persona]
	maxToolsPerTurn    int

	// reflectorFn is the per-tool-failure reflection callback. Nil
	// means "use a.reflect", which calls the classification-tier model
	// with a diagnostic prompt. Tests substitute a synchronous stub so
	// the reflexion logic can be exercised without an SDK mock.
	reflectorFn reflectFunc

	// prospectiveFn is the pre-dispatch critique callback (Batch A).
	// Fires before critical-risk tools run; produces a structured
	// risk assessment the main model sees alongside the tool result.
	// Nil means "use a.prospective"; tests substitute a sync stub.
	prospectiveFn prospectiveFunc

	// routerFn is the per-turn tool-group router. Nil means "disabled"
	// — the full catalog is sent to the main model every turn (the
	// historical behaviour). EnableDynamicCatalog assigns
	// a.routeGroups here. Tests substitute a synchronous stub.
	routerFn routerFunc

	// snapshotMgr captures pre-write copies of Flipper SD files so
	// /rewind can roll them back. Nil disables the feature (Store
	// calls are skipped silently). See internal/snapshot.
	snapshotMgr *snapshot.Manager

	// verifierFn is the chain-of-verification (P1-16) pre-deploy
	// callback. Nil means "use a.verifyPayload", the production
	// Haiku-backed verifier. Tests install a synchronous stub.
	verifierFn verifyFunc

	// detectorEngine runs registered detectors after each tool call
	// and surfaces their verdicts on the tool result (P1-10). Nil
	// disables the feature (no engine = no verdicts).
	detectorEngine *rules.DetectorEngine

	// breakerCounter tracks per-tool consecutive same-kind errors
	// (P3-28 second half). Trips after N matching failures and the
	// dispatcher prepends a structured <circuit-breaker-open> block
	// to the next tool result so the model sees an explicit
	// escalation cue instead of looping. Nil disables the feature
	// entirely — the dispatcher then falls through unchanged.
	breakerCounter *breaker.Counter

	// attackIdx maps tools to MITRE ATT&CK technique IDs. Consumed
	// by the /report generator and the runtime attack-constraint
	// filter. Set via SetAttackIndex; nil disables both.
	attackIdx *attack.Index
	// attackConstraint filters the per-turn tool catalog to tools
	// tagged with at least one of these technique IDs. Empty
	// disables the filter (all tools pass through the ATT&CK gate).
	attackConstraint []string

	// ragIndex is the lexical (BM25) retriever over the bundled
	// documentation corpus (Batch D). Nil falls back to the default
	// embedded index on first docs_search call.
	ragIndex *rag.Index

	// targetMem is the persistent target store (Batch B). Nil disables
	// the target_* tools and short-circuits Remember/Recall — operators
	// who haven't opted in or who hit a DB open failure at startup
	// still get a working agent without the facts feature.
	targetMem *targetmem.Store

	// opMode is the active operation mode (Standard, Recon, Intel,
	// Stealth, Assault). Default is mode.ModeStandard, which permits
	// every tool group — preserving historical behaviour for builds /
	// callers that never set a mode.
	//
	// Layered after readOnly: dispatch consults readOnly first; mode
	// is consulted only when readOnly is false. The originally-planned
	// v0.20.0 removal didn't happen because mode-as-coarse-capability-
	// filter remained useful alongside the read-only rail.
	//
	// Stored in an atomic.Pointer instead of under a.mu because dispatch
	// is invoked from Run with a.mu already held — taking it again in
	// Mode() would deadlock (Go mutexes aren't re-entrant). Atomic read
	// in dispatch's hot path also avoids contention with concurrent
	// mu-protected field updates elsewhere in Agent.
	opMode atomic.Pointer[mode.Mode]

	// readOnly is the v0.19.0 safety rail. When true, dispatch refuses
	// any spec whose Risk is above risk.Low (writes, transmits,
	// emulation, execution, payload generation). Independent of the
	// confirm gate — read-only is a hard no, not "ask first".
	//
	// atomic.Bool so dispatch reads it without taking a.mu (matching
	// opMode's rationale). Default false preserves historical CRUD
	// behaviour for callers that never set it.
	readOnly atomic.Bool

	// latestUIContext carries the navigation state forwarded from the web UI.
	latestUIContext atomic.Pointer[agentUIContext]

	// titleGenInflight tracks session ids whose Haiku title generation
	// is in flight (or done) so autoSaveLocked fires the call at most
	// once per process. Cleared only on Agent destruction; the cost is
	// trivially small (one map entry per session ever resumed).
	titleGenInflight map[string]bool
}

// agentUIContext is the latest view+path the web UI reported.
type agentUIContext struct {
	View string
	Path string
}

// SetDetectorEngine installs a rules.DetectorEngine. When set, the
// agent runs registered detectors after every tool dispatch and
// appends each verdict in a <detector-verdict> block on the tool
// result so the main model can factor the signal into its next turn
// (e.g. a deauth that reports success but the detector calls
// suspicious).
func (a *Agent) SetDetectorEngine(e *rules.DetectorEngine) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.detectorEngine = e
}

// SetUIContext records the latest browser navigation state (view + path)
// so buildUIContextBlock can inject it into the next turn prefix.
func (a *Agent) SetUIContext(view, path string) {
	a.latestUIContext.Store(&agentUIContext{View: view, Path: path})
}

// UIContext returns the last view and path the web UI reported.
func (a *Agent) UIContext() (view, path string) {
	if v := a.latestUIContext.Load(); v != nil {
		return v.View, v.Path
	}
	return "", ""
}

// SetSnapshotManager wires an optional pre-write SD snapshotter.
// Writes through fileformat_edit capture the prior file content into
// the per-session snapshot tree so /rewind can roll them back. Nil
// disables the feature.
func (a *Agent) SetSnapshotManager(m *snapshot.Manager) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.snapshotMgr = m
}

// SnapshotManager returns the currently installed snapshot manager,
// or nil when snapshots are disabled. Exposed for /rewind list/restore
// commands that operate against the live agent.
func (a *Agent) SnapshotManager() *snapshot.Manager {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snapshotMgr
}

func New(client *anthropic.Client, flip *flipper.Flipper, cfg *config.Config) *Agent {
	a := &Agent{
		client:           client,
		flipper:          flip,
		cfg:              cfg,
		model:            cfg.Model,
		confirmThreshold: risk.High,
		maxToolsPerTurn:  defaultMaxToolCallsPerTurn,
	}
	a.SetMode(mode.ModeStandard)

	// Set up vision analyzer
	a.vision = vision.New(client, cfg.Model)

	return a
}

// SetMode swaps the active operation mode. The mode constrains which
// tool groups dispatch will accept; see internal/mode for the
// per-mode allow-lists. An empty Mode resets to mode.ModeStandard
// (the default, behaviour-preserving profile).
//
// Layers after SetReadOnly: dispatch consults readOnly first, then
// mode. Both gates are independently useful — read-only is a hard
// no-write rail; mode is a coarse capability profile (e.g. Recon
// blocks transmit groups; Stealth blocks high-noise groups).
func (a *Agent) SetMode(m mode.Mode) {
	if m == "" {
		m = mode.ModeStandard
	}
	a.opMode.Store(&m)
}

// SetReadOnly toggles the read-only safety rail. When v is true,
// dispatch refuses any tool whose Spec.Risk is above risk.Low — no
// writes, no transmits, no emulation, no payload generation. Buys an
// operator a hard guarantee that the session cannot mutate the
// Flipper, the Marauder, the SD card, or anything off-host.
//
// The flag is independent of the confirm gate — read-only is a refusal,
// not a "confirm first". Pair with --confirm-risk if you also want
// confirms on Low-risk reads (e.g. audit_export from a sensitive
// session).
//
// Lock-free atomic, matching SetMode's contract for the same reason
// (dispatch reads it under a.mu held, must not re-acquire).
func (a *Agent) SetReadOnly(v bool) {
	a.readOnly.Store(v)
}

// ReadOnly reports whether the read-only safety rail is engaged.
// Used by REPL banner rendering, /status, and the catalog narrowing
// in buildTools.
func (a *Agent) ReadOnly() bool {
	return a.readOnly.Load()
}

// Mode returns the currently-active operation mode. Returns
// mode.ModeStandard when no mode has been explicitly set. Lock-free
// because dispatch is called from Run with a.mu already held; this
// getter would otherwise deadlock.
func (a *Agent) Mode() mode.Mode {
	if p := a.opMode.Load(); p != nil {
		return *p
	}
	return mode.ModeStandard
}

func (a *Agent) SetMarauder(m *marauder.Marauder) { a.marauder = m }

// Marauder returns the attached Marauder client, or nil when unconnected.
// Read-only access for callers (e.g. setup.go probing firmware) that hold
// the agent reference but should not own the client lifecycle.
func (a *Agent) Marauder() *marauder.Marauder { return a.marauder }

// SetBruce attaches a Bruce ESP32 backend client. Nil disables Bruce
// Specs (handlers short-circuit via [tools.Deps.RequireBruce]).
func (a *Agent) SetBruce(c *bruce.Client) { a.bruce = c }

// SetFaultier attaches a Faultier USB voltage-glitcher client. Nil
// disables glitch_* Specs.
func (a *Agent) SetFaultier(c *faultier.Client) { a.faultier = c }

// SetBusPirate attaches a Bus Pirate 5 universal-bus probe client. Nil
// disables buspirate_* Specs.
func (a *Agent) SetBusPirate(c *buspirate.Client) { a.buspirate = c }

// SetBreaker attaches the per-tool circuit breaker (P3-28 second
// half). When non-nil, every tool error feeds the breaker and a
// trip prepends a <circuit-breaker-open> block to the model-facing
// output so the LLM sees an explicit "stop hammering this" cue
// instead of looping. Pass nil to disable; production wiring uses
// breaker.New(0) to pick up the default 3-strike threshold.
func (a *Agent) SetBreaker(b *breaker.Counter) { a.breakerCounter = b }

// Breaker returns the active circuit-breaker counter, or nil when
// the feature is disabled. Exposed for /stats and operator-facing
// /reset-breaker commands.
func (a *Agent) Breaker() *breaker.Counter { return a.breakerCounter }

// SetAuditLog attaches the audit log and wires the per-session
// PersonaContextResolver (P3-31) so each recorded entry picks up the
// active persona's version + a hash of the system prompt that would
// be presented for the current tool config. The resolver is a closure
// over the agent so a mid-session persona switch updates the next
// audit row's PersonaVersion + PromptHash without a re-wire.
func (a *Agent) SetAuditLog(l *audit.Log) {
	a.auditLog = l
	if l == nil {
		return
	}
	l.SetPersonaContextResolver(func() audit.PersonaContext {
		p := a.personaAtomic.Load()
		var version string
		if p != nil {
			version = p.Version
		}
		// hasWiFi/hasWorkflows mirror BuildSystemPrompt's rendering
		// rules so the hash matches what the agent would have shown
		// the model on a turn started right now.
		hasWiFi := a.marauder != nil
		return audit.PersonaContext{
			PersonaVersion: version,
			PromptHash:     SystemPromptHash(p, hasWiFi, true),
		}
	})
}
func (a *Agent) SetGenerator(g *generate.Generator)      { a.generator = g }
func (a *Agent) SetGenLLM(p provider.Provider)           { a.genLLM = p }
func (a *Agent) SetToolStatusCallback(f func(ToolEvent)) { a.toolStatusCb = f }
func (a *Agent) SetTextDeltaCallback(f func(TextDelta))  { a.textDeltaCb = f }

// SetToolStreamCallback registers a per-frame callback for tools
// that opted into streaming dispatch (P3-28 first half). The
// callback is invoked once per partial frame, in arrival order;
// dispatch blocks until the consumer drain completes so no frame
// arrives after the dispatch returns. Pass nil to disable
// streaming dispatch entirely — opted-in tools then fall back to
// their non-streaming Handler.
//
// Return value semantics: true keeps the stream alive, false
// triggers abort-early. On false, dispatch closes the sink's
// Aborted() channel and cancels the per-tool context; honouring
// producers wrap up and return a partial result via the normal
// final-string path. Producers that ignore both signals will run
// to completion (no forced kill) — abort-early is cooperative.
//
// SECURITY CONTRACT: frame.Bytes is RAW tool output — firmware log
// lines, RF scan rows, device names — i.e. attacker-controllable bytes
// that may contain ANSI/control sequences. Unlike the final return
// string (which dispatch runs through quarantineOutput's
// sanitizeControlChars + injection wrapping), per-frame data is NOT
// sanitised at the dispatch boundary. A consumer MUST neutralise control
// characters before rendering a frame to a terminal or UI, or a hostile
// capture can hijack the operator's display. The REPL does this in
// cmd/promptzero/repl.go renderStreamFrame (quote-on-control); any new
// consumer (a web cockpit stream, a fresh UI) must do the same.
func (a *Agent) SetToolStreamCallback(f func(streaming.Frame) bool) { a.toolStreamCb = f }

// Usage reports token consumption for one successful streamOnce call.
// InputTokens and OutputTokens are the usual Anthropic counters; the
// two cache fields track prompt-cache hits (read) and misses that
// created a new cache (creation). A healthy session shows steadily
// growing CacheReadTokens and occasional CacheCreationTokens spikes
// when the cached prefix rotates.
type Usage struct {
	InputTokens         int64
	OutputTokens        int64
	CacheReadTokens     int64
	CacheCreationTokens int64

	// Model identifies the upstream model that produced this usage
	// block. Populated from the resolved tier-model for each call (e.g.
	// the plan tier for a main turn, the classify tier for a router
	// narrowing). Downstream cost trackers can use it to bill at the
	// per-call rate via cost.Tracker.AddUsageFullForModel — falling
	// back to the tracker's configured model when Model is "".
	Model string
}

// SetUsageCallback registers a per-response token counter. Fires once
// per successful streamOnce with the message's Usage block, including
// prompt-cache read / creation tokens. Pass nil to disable.
func (a *Agent) SetUsageCallback(f func(u Usage)) { a.usageCb = f }

// fireTierUsage reports a non-streaming tier-call's usage to the
// usage callback. Pre-v0.196 the reflexion / consensus / prospective
// / router / verify / session-autoname call sites bypassed the cost
// callback entirely, so their tokens never reached the dashboard.
// The model arg carries the actual upstream model (resolved via
// modelForLocked at the call site) so cost.Tracker.AddUsageFullForModel
// bills at the tier's real rate.
//
// Concurrency contract matches the call sites: they all hold a.mu, so
// reading a.usageCb without re-locking is safe.
func (a *Agent) fireTierUsage(model string, u anthropic.Usage) {
	if a.usageCb == nil {
		return
	}
	safeCallUsage(a.usageCb, Usage{
		InputTokens:         u.InputTokens,
		OutputTokens:        u.OutputTokens,
		CacheReadTokens:     u.CacheReadInputTokens,
		CacheCreationTokens: u.CacheCreationInputTokens,
		Model:               model,
	})
}

// SetStreamErrorCallback registers a hook that fires when the upstream
// Messages.NewStreaming call returns an error. Wired to the cost
// Tracker so consecutive network failures flip the offline banner.
func (a *Agent) SetStreamErrorCallback(f func(err error)) { a.streamErrCb = f }

// SetConfirmCallback registers an interactive gate consulted before any
// tool whose classified risk meets or exceeds the confirm threshold runs.
// Passing nil disables the gate. Non-interactive surfaces (MCP, web) leave
// this unset so tools execute without prompting.
func (a *Agent) SetConfirmCallback(f ConfirmFunc) { a.confirmCb = f }

// safeCallTextDelta invokes the operator-supplied delta callback with a
// deferred recover. A buggy callback that panics would otherwise crash
// the agent mid-stream — the recover converts the panic into a logged
// warning and lets streamOnce continue accumulating the message.
func safeCallTextDelta(cb func(TextDelta), d TextDelta) {
	defer func() {
		if r := recover(); r != nil {
			obs.Default().Warn("agent_text_delta_cb_panicked",
				"recovered", fmt.Sprintf("%v", r))
		}
	}()
	cb(d)
}

// safeCallStreamErr is the recover-wrapped invocation for stream-error
// callbacks. Same shape as safeCallTextDelta.
func safeCallStreamErr(cb func(error), err error) {
	defer func() {
		if r := recover(); r != nil {
			obs.Default().Warn("agent_stream_err_cb_panicked",
				"recovered", fmt.Sprintf("%v", r))
		}
	}()
	cb(err)
}

// safeCallUsage is the recover-wrapped invocation for usage callbacks.
// A panic here would lose token-accounting for the turn but must not
// crash the agent (which has just successfully completed the API call).
func safeCallUsage(cb func(Usage), u Usage) {
	defer func() {
		if r := recover(); r != nil {
			obs.Default().Warn("agent_usage_cb_panicked",
				"recovered", fmt.Sprintf("%v", r))
		}
	}()
	cb(u)
}

// safeCallToolStatus is the recover-wrapped invocation for the
// per-tool status callback. Operators install this to drive a UI
// progress indicator; a panic in it would otherwise crash the agent
// during a tool dispatch — even after the tool itself succeeded.
func safeCallToolStatus(cb func(ToolEvent), e ToolEvent) {
	defer func() {
		if r := recover(); r != nil {
			obs.Default().Warn("agent_tool_status_cb_panicked",
				"phase", e.Phase, "tool", e.Name,
				"recovered", fmt.Sprintf("%v", r))
		}
	}()
	cb(e)
}

// safeCallToolStream is the recover-wrapped invocation for the
// per-frame stream callback (toolStreamCb). Mirrors safeCallToolStatus
// — the consumer goroutine in dispatchStreaming reads frames in a
// tight loop, and a panic in the host callback (REPL UI writing to a
// closed terminal, web cockpit reading from a closed WS connection,
// etc.) would otherwise crash the agent process mid-dispatch. We
// log + treat the panic as `keep=false` so the stream aborts and the
// drain proceeds cleanly.
func safeCallToolStream(cb func(streaming.Frame) bool, f streaming.Frame) (keep bool) {
	keep = true
	defer func() {
		if r := recover(); r != nil {
			obs.Default().Warn("agent_tool_stream_cb_panicked",
				"tool", f.Tool, "seq", f.Seq,
				"recovered", fmt.Sprintf("%v", r))
			keep = false
		}
	}()
	return cb(f)
}

// SetConfirmIdleTimeout overrides how long confirmWithIdleTimeout waits for
// an operator response before treating silence as a deny. A zero or negative
// value restores the default (5 minutes).
func (a *Agent) SetConfirmIdleTimeout(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if d <= 0 {
		a.confirmIdleTimeout = 0
		return
	}
	a.confirmIdleTimeout = d
}

// confirmIdleTimeout caps how long Run will hold a.mu waiting for the user to
// answer a confirmation prompt. After this, we treat silence as a deny so
// the session isn't wedged by a walked-away operator.
const confirmIdleTimeout = 5 * time.Minute

// confirmWithIdleTimeout invokes the confirm callback in a goroutine and
// enforces confirmIdleTimeout. On timeout the caller gets
// {DecisionDeny} and Run proceeds as if the user declined.
//
// Concurrency contract: callers MUST NOT hold a.mu across this call
// (Run releases a.mu around the confirm gate specifically so field
// readers don't block on a walked-away operator). turnMu SHOULD be
// held to prevent a second Run from racing mid-gate. The callback
// itself is snapshotted under a brief lock to stay safe against
// SetConfirmCallback.
//
// The callback receives a cancellable child ctx derived from the caller's
// ctx. It is cancelled on timeout, on parent ctx cancellation, or on a
// successful return — whichever comes first. Callbacks must honour
// ctx.Done() to avoid blocking after the idle deadline fires; the REPL
// implementation already does this.
func (a *Agent) confirmWithIdleTimeout(ctx context.Context, req ConfirmRequest) ConfirmResponse {
	// Snapshot the callback and timeout under a brief lock BEFORE
	// spawning the goroutine. Using local copies means a concurrent
	// SetConfirmCallback / SetConfirmIdleTimeout can't race the
	// callback invocation, and the -race detector has no complaint
	// regardless of how callbacks get swapped over a session's
	// lifetime. Callers do not need to hold a.mu when entering this
	// function — Run specifically releases it so other field readers
	// aren't blocked on a walked-away operator.
	a.mu.Lock()
	cb := a.confirmCb
	timeout := a.confirmIdleTimeout
	a.mu.Unlock()
	if timeout <= 0 {
		timeout = confirmIdleTimeout
	}
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	t := time.NewTimer(timeout)
	defer t.Stop()
	ch := make(chan ConfirmResponse, 1)
	// The goroutine relies on childCtx being cancelled (via the
	// deferred cancel() above) so a well-behaved callback will
	// unblock promptly after timeout / ctx cancel. Callbacks that
	// only watch the outer ctx are API violations; the contract is
	// documented on ConfirmFunc. SafeGo recovers panics — the select
	// then falls through to ctx/timer and returns DecisionDeny.
	obs.SafeGo("agent.confirm_callback", func() { ch <- cb(childCtx, req) })
	select {
	case r := <-ch:
		return r
	case <-ctx.Done():
		return ConfirmResponse{Decision: DecisionDeny}
	case <-t.C:
		return ConfirmResponse{Decision: DecisionDeny}
	}
}

// compactHistoryLocked trims the in-memory history to at most maxHistory
// entries, keeping the first 2 (initial context) and the most-recent
// (maxHistory-2). It must be called with a.mu held. It is safe to call
// when len(a.history) <= maxHistory — it is a no-op in that case.
//
// Invariant: the Anthropic API requires every assistant tool_use block to
// be paired with a following user tool_result block. compactHistoryLocked
// ensures the kept history never violates this in two places:
//  1. The anchor itself (default a.history[:2]) — extended forward when
//     the last anchor message has a tool_use, so the matching tool_result
//     is kept with it. Without this extension, sessions whose first
//     assistant turn invokes a tool (the common case) generate a corrupt
//     payload after first compaction: messages.1 has a tool_use whose
//     tool_result is in the discarded window, and the API rejects every
//     subsequent turn with a 400.
//  2. The tail boundary — shifted earlier (up to 4 positions) when the
//     first tail entry is a user-of-tool-results paired with the
//     immediately-preceding assistant tool_use.
//
// If neither protection can be satisfied, compaction is skipped this call.
func (a *Agent) compactHistoryLocked() {
	if len(a.history) <= maxHistory {
		return
	}

	// Resolve the anchor end. Default is 2; extend forward whenever the
	// last anchor message is an assistant with a tool_use, swallowing the
	// matching user tool_result. Cap at maxAnchorExtension so a malformed
	// burst of tool_use/result pairs at the start can't grow the anchor
	// unboundedly.
	const maxAnchorExtension = 8
	anchorEnd := 2
	if len(a.history) < anchorEnd {
		// Fewer than 2 entries — nothing to compact.
		return
	}
	for ext := 0; ext < maxAnchorExtension; ext++ {
		last := a.history[anchorEnd-1]
		if last.Role != anthropic.MessageParamRoleAssistant || !hasToolUse(last) {
			break // anchor ends cleanly
		}
		// Anchor's last entry has a tool_use; extend by 1 to include
		// the matching tool_result.
		if anchorEnd >= len(a.history) {
			// No room to extend (history shorter than needed). Drop the
			// anchor entirely — better to lose initial context than ship
			// a corrupt payload.
			anchorEnd = 0
			break
		}
		next := a.history[anchorEnd]
		if next.Role != anthropic.MessageParamRoleUser || !allToolResults(next) {
			// The next entry isn't the matching tool_result. Drop anchor.
			anchorEnd = 0
			break
		}
		anchorEnd++
	}

	// Candidate split: keep anchor + last (maxHistory - anchorEnd).
	splitIdx := len(a.history) - (maxHistory - anchorEnd)
	if splitIdx <= anchorEnd {
		// History has grown only marginally past maxHistory; the anchor
		// extension already covers the slack. Skip this call.
		return
	}
	// Safety search: shift splitIdx earlier if it lands in the middle of a
	// tool_use/tool_result pair (up to 4 positions back).
	for shift := 0; shift <= 4; shift++ {
		idx := splitIdx - shift
		if idx <= anchorEnd {
			// No room to compact without overlapping the anchor.
			return
		}
		msg := a.history[idx]
		if msg.Role == anthropic.MessageParamRoleUser && allToolResults(msg) {
			// Check the message just before: if it is an assistant message
			// containing tool_use blocks, both must be kept together.
			if idx > 0 {
				prev := a.history[idx-1]
				if prev.Role == anthropic.MessageParamRoleAssistant && hasToolUse(prev) {
					// This pair must not be split; try shifting further.
					continue
				}
			}
		}
		// splitIdx is safe.
		splitIdx = idx
		break
	}
	tail := a.history[splitIdx:]
	compacted := make([]anthropic.MessageParam, anchorEnd, maxHistory)
	copy(compacted, a.history[:anchorEnd])
	a.history = append(compacted, tail...)
}

// allToolResults reports whether every content block in msg is a tool_result.
// Used by compactHistoryLocked to identify user messages that are paired with
// a preceding assistant tool_use message.
func allToolResults(msg anthropic.MessageParam) bool {
	if len(msg.Content) == 0 {
		return false
	}
	for _, b := range msg.Content {
		if b.OfToolResult == nil {
			return false
		}
	}
	return true
}

// hasToolUse reports whether msg contains at least one tool_use content block.
func hasToolUse(msg anthropic.MessageParam) bool {
	for _, b := range msg.Content {
		if b.OfToolUse != nil {
			return true
		}
	}
	return false
}

// SetConfirmThreshold configures which risk level triggers a confirmation
// prompt. Tools classified at or above the threshold are gated. Defaults
// to risk.High.
func (a *Agent) SetConfirmThreshold(l risk.Level) { a.confirmThreshold = l }

// SetMaxToolsPerTurn overrides the per-turn tool-call cap. A non-positive
// value resets the cap to the default. Callers typically leave this alone
// — it exists so tests can force early termination and future config can
// expose the knob without changing Run's internals.
func (a *Agent) SetMaxToolsPerTurn(n int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n <= 0 {
		a.maxToolsPerTurn = defaultMaxToolCallsPerTurn
		return
	}
	a.maxToolsPerTurn = n
}

// SetPersona swaps the active operator persona. The persona's SystemPrompt
// replaces the default preamble on the next streamed request and its tool
// allowlist filters the advertised tool set. Passing nil clears any active
// persona and restores default behaviour. Callers typically pair this with
// Reset() so a mid-turn handoff doesn't sandwich two system prompts inside
// the same assistant context.
func (a *Agent) SetPersona(p *persona.Persona) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.persona = p
	a.personaAtomic.Store(p)
}

// Persona returns the currently active persona, or nil when the default
// (unrestricted) behaviour is in effect.
func (a *Agent) Persona() *persona.Persona {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.persona
}

// PersonaSnapshot returns the currently active persona without taking a.mu.
// Intended for read-only callers (debug endpoints, status panels) that must
// remain responsive even while Run holds the agent mutex. Returns nil when
// the default persona is active.
func (a *Agent) PersonaSnapshot() *persona.Persona {
	return a.personaAtomic.Load()
}

func (a *Agent) Run(ctx context.Context, userInput string) (string, error) {
	// turnMu enforces single-turn-at-a-time; mu is field-level and
	// gets briefly released during the confirm gate so other readers
	// (SetPersona, status panels) aren't blocked by a walked-away
	// operator.
	a.turnMu.Lock()
	defer a.turnMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()

	// v0.23 — pre-flight budget gate. The cost tracker fires a warn
	// callback at 80% and a hit callback at 100%, but pre-this-fix
	// nothing actually stopped the next turn from spending past the
	// cap. Check at the top of Run so we refuse before any tokens
	// burn — the operator either raises the cap (/budget set $X) or
	// wraps up the session. The check runs under a.mu, but the
	// callback shouldn't reach back into agent state — it's just a
	// boolean predicate against the tracker.
	if a.budgetCheckCb != nil {
		if err := a.budgetCheckCb(); err != nil {
			return "", err
		}
	}

	// Attach a fresh trace ID (or reuse the caller's) so every log line,
	// audit row, and tool event emitted inside this turn shares one ID.
	// The discarded second return value is the trace ID string, not a
	// cleanup func — TraceID(ctx) recovers it downstream when needed.
	ctx, _ = obs.WithTrace(ctx)
	obs.FromCtx(ctx).Info("turn_started", "input_len", len(userInput))

	// Open a gen_ai.agent.turn OTel span. InitOTel installs a noop
	// tracer when OTEL_EXPORTER_OTLP_ENDPOINT is unset, so this costs
	// nothing in deployments that don't enable tracing.
	turnModel := a.modelForLocked(TierPlan)
	ctx, turnSpan := obs.StartAgentTurn(ctx, turnModel, len(userInput))
	defer turnSpan.End()

	// Device-state oracle: inject a fresh <device-state> JSON block as a
	// prefix on the user turn so the model stops asking "what's
	// connected?" / "what mode are you in?" every few turns. Stays
	// outside the prompt-cache window because the snapshot changes
	// every few seconds (see state_prompt.go).
	uiView, uiPath := a.UIContext()
	userInput = buildUIContextBlock(uiView, uiPath) + buildDeviceStateBlock(ctx, a.flipper) + userInput

	a.history = append(a.history, anthropic.NewUserMessage(
		anthropic.NewTextBlock(userInput),
	))

	a.compactHistoryLocked()

	// All tools are in the central registry; buildTools() covers them all.
	tools := buildTools()

	// Read-only catalog narrowing. When the safety rail is engaged we
	// also strip non-Low specs from the LLM's catalog so the model
	// doesn't waste a turn planning a tool it would only get refused
	// at dispatch. The dispatch check above remains the authoritative
	// gate — this is purely a token-saving + UX improvement.
	if a.readOnly.Load() {
		tools = filterToolsToReadOnly(tools)
	}

	// Persona-based tool narrowing layers on top of the read-only
	// rail above: read-only is the safety gate, persona Tools is a
	// positive allowlist that lets a persona scope the catalog
	// (e.g. a "lecture" persona exposing only inspect-and-explain
	// tools). User personas under ~/.promptzero/personas/*.yaml
	// that specify allowlists are honoured here.
	if a.persona != nil && len(a.persona.Tools) > 0 {
		tools = persona.FilterTools(tools, a.persona.Tools)
	}
	// WiFi framing is appended only when the filtered tool set still exposes
	// WiFi capabilities — personas that prune them (defender, rf-recon, etc.)
	// should not hear about an ESP32 they can't address. The hasWiFi check
	// runs *before* dynamic narrowing so the system prompt stays stable
	// (and therefore cache-friendly) across turns.
	hasWiFi := a.marauder != nil && hasWiFiTool(tools)
	sysPrompt := BuildSystemPrompt(a.persona, hasWiFi, true)

	// Dynamic tool-catalog narrowing (opt-in via EnableDynamicCatalog):
	// ask a classification-tier model which groups are relevant to this
	// turn and trim the tool catalog accordingly. Any router failure
	// falls back to the full set so correctness is never sacrificed for
	// cost.
	tools = narrowTools(ctx, userInput, tools, a.routerFn)

	// ATT&CK constraint filter (P1-07): when the operator has pinned
	// the session to one or more technique IDs, drop tools that
	// aren't tagged with any of those techniques. Always-on meta
	// groups survive. See router.go's narrowToolsByAttack for
	// correctness floors.
	if len(a.attackConstraint) > 0 && a.attackIdx != nil {
		tools = narrowToolsByAttack(tools, a.attackIdx, a.attackConstraint)
	}

	maxTools := a.maxToolsPerTurn
	if maxTools <= 0 {
		maxTools = defaultMaxToolCallsPerTurn
	}
	toolCallsThisTurn := 0
	// Cap on how many tool failures in this user turn are allowed to
	// trigger a reflexion call — see reflexion.go. Incremented by
	// maybeAppendReflection only when the reflector actually produced
	// useful text.
	reflectionsThisTurn := 0
	// prospectiveThisTurn caps how many critical tools get a
	// pre-dispatch critique per user turn (Batch A). Bounded so a
	// multi-step attack chain doesn't mint an arbitrary Haiku bill.
	prospectiveThisTurn := 0
	// pendingRevisions collects revision prompts emitted by
	// DecisionRevise in the current turn. After the tool_results
	// batch is flushed, each revision is appended as a fresh user
	// message so the next streamOnce sees it alongside the
	// "operator requested revision" tool_result and can re-plan the
	// call with the operator's edit.
	var pendingRevisions []string

	for {
		resp, err := a.streamOnceWithRetry(ctx, sysPrompt, tools)
		if err != nil {
			return "", fmt.Errorf("claude API: %w", err)
		}

		var textParts []string
		var toolCalls []anthropic.ContentBlockUnion
		for _, block := range resp.Content {
			switch block.Type {
			case "text":
				textParts = append(textParts, block.Text)
			case "tool_use":
				toolCalls = append(toolCalls, block)
			}
		}

		if len(toolCalls) == 0 {
			a.history = append(a.history, anthropic.NewAssistantMessage(toUnionBlocks(resp.Content)...))
			a.autoSaveLocked()
			return strings.Join(textParts, ""), nil
		}

		// Per-turn tool-call cap: if accepting this batch would push the
		// running count past the cap, synthesise a cap-reached tool_result
		// for each pending tool_use and break without executing any tools
		// in this batch. Emitting the result for every tool_use keeps the
		// assistant/user pair well-formed for the history compaction step.
		if toolCallsThisTurn+len(toolCalls) > maxTools {
			obs.FromCtx(ctx).Warn("tool_call_cap_reached",
				"cap", maxTools,
				"calls_so_far", toolCallsThisTurn,
				"pending", len(toolCalls),
			)
			a.history = append(a.history, anthropic.NewAssistantMessage(toUnionBlocks(resp.Content)...))
			capMsg := fmt.Sprintf("tool call cap reached (%d calls in this turn); returning to user", maxTools)
			var capResults []anthropic.ContentBlockParamUnion
			for _, tc := range toolCalls {
				capResults = append(capResults, anthropic.NewToolResultBlock(tc.ID, capMsg, true))
			}
			a.history = append(a.history, anthropic.NewUserMessage(capResults...))
			a.compactHistoryLocked()
			a.autoSaveLocked()
			return capMsg, nil
		}
		toolCallsThisTurn += len(toolCalls)

		a.history = append(a.history, anthropic.NewAssistantMessage(toUnionBlocks(resp.Content)...))

		var toolResults []anthropic.ContentBlockParamUnion
		// approveAllRemaining gates future tools in the same turn that
		// are at or below approveAllCeiling. Without the ceiling, an
		// "approve all" on a Medium-risk tool would silently authorise
		// a subsequent High-risk tool — operators reasonably expect
		// "approve all" to scope to what they just saw, not escalate.
		// Critical is always gated independently (see the `gated` expr
		// below).
		var (
			approveAllRemaining bool
			approveAllCeiling   risk.Level
		)
		for _, tc := range toolCalls {
			input := json.RawMessage(tc.Input)
			toolRisk := risk.Classify(tc.Name)
			// For run_payload, resolve the effective risk of the underlying
			// operation from the path argument and use the maximum of the two.
			// This ensures a run_payload that dispatches to a Critical op is
			// always gated as Critical, not just as the nominal High of the
			// run_payload tool name.
			if tc.Name == "run_payload" {
				var rp struct {
					Path string `json:"path"`
				}
				if err := json.Unmarshal(tc.Input, &rp); err == nil {
					_, resolved := resolveRunPayloadRisk(rp.Path)
					if resolved > toolRisk {
						toolRisk = resolved
					}
				}
			}

			// Risk gate: consult the confirm callback before destructive tools run.
			// Denied calls are short-circuited with a synthetic tool_result so the
			// model gets a clean "user denied" turn instead of a dangling tool_use.
			//
			// Critical tools are *always* gated, even if the operator already
			// said "approve all remaining" for an earlier tool in the same
			// turn. Approve-all is a convenience for reducing prompt fatigue
			// on moderate actions; it should never silently authorise a
			// critical one.
			// Audit gate: refuse risk≥High actions when no audit log is
			// initialised — running a destructive tool with no audit trail
			// would break the project's safety posture.
			if err := audit.RequireOpen(a.auditLog, toolRisk); err != nil {
				msg := err.Error()
				if a.toolStatusCb != nil {
					safeCallToolStatus(a.toolStatusCb, ToolEvent{Phase: "start", Name: tc.Name, Input: input})
					safeCallToolStatus(a.toolStatusCb, ToolEvent{Phase: "finish", Name: tc.Name, Input: input, Output: msg, Err: true})
				}
				toolResults = append(toolResults, anthropic.NewToolResultBlock(tc.ID, msg, true))
				continue
			}
			// Approve-all only auto-approves tools at or below the risk
			// level the operator was prompted on. Critical is always
			// gated regardless. A subsequent tool above the ceiling
			// re-prompts; the operator can extend the ceiling by
			// approve-all'ing again at that higher level.
			gated := toolRisk == risk.Critical || !approveAllRemaining || toolRisk > approveAllCeiling
			if a.confirmCb != nil && gated && toolRisk >= a.confirmThreshold {
				// Release a.mu while the confirm callback waits on
				// the operator. turnMu still guards against a
				// second Run starting; field readers (SetPersona,
				// PersonaSnapshot, the observability status panel)
				// can now proceed during the idle window.
				a.mu.Unlock()
				resp := a.confirmWithIdleTimeout(ctx, a.buildConfirmRequest(tc.Name, input, toolRisk))
				a.mu.Lock()
				switch resp.Decision {
				case DecisionDeny:
					const denyMsg = "user denied this action"
					if a.toolStatusCb != nil {
						safeCallToolStatus(a.toolStatusCb, ToolEvent{Phase: "start", Name: tc.Name, Input: input})
						safeCallToolStatus(a.toolStatusCb, ToolEvent{Phase: "finish", Name: tc.Name, Input: input, Output: denyMsg, Err: true})
					}
					if a.auditLog != nil {
						a.auditLog.RecordCtx(ctx, tc.Name, input, denyMsg, toolRisk.String(), audit.LevelAction, 0, false)
					}
					toolResults = append(toolResults, anthropic.NewToolResultBlock(tc.ID, denyMsg, true))
					continue
				case DecisionRevise:
					// Operator asked for a revision instead of running
					// the tool. Synthesise a tool_result marking it as
					// skipped, then inject the revision text as a
					// fresh user turn via the pending revision stash
					// so the next streamOnce sees it alongside the
					// tool_result and can re-plan.
					revisionText := strings.TrimSpace(resp.Revision)
					if revisionText == "" {
						revisionText = "(no revision text provided)"
					}
					resultMsg := "operator requested revision instead of running this tool: " + revisionText
					if a.toolStatusCb != nil {
						safeCallToolStatus(a.toolStatusCb, ToolEvent{Phase: "start", Name: tc.Name, Input: input})
						safeCallToolStatus(a.toolStatusCb, ToolEvent{Phase: "finish", Name: tc.Name, Input: input, Output: resultMsg, Err: true})
					}
					if a.auditLog != nil {
						a.auditLog.RecordCtx(ctx, tc.Name, input, resultMsg, toolRisk.String(), audit.LevelAction, 0, false)
					}
					toolResults = append(toolResults, anthropic.NewToolResultBlock(tc.ID, resultMsg, true))
					// Track the revision so we can inject it after
					// the tool_result batch closes (one revision
					// message per turn is plenty — subsequent
					// reviews stack naturally).
					pendingRevisions = append(pendingRevisions, revisionText)
					continue
				case DecisionApproveAll:
					approveAllRemaining = true
					// Cap the auto-approve scope at the risk level
					// just shown. A later High-risk tool in the same
					// turn (when the operator just approve-all'd a
					// Medium one) re-prompts.
					if toolRisk > approveAllCeiling {
						approveAllCeiling = toolRisk
					}
				}
			}

			if a.toolStatusCb != nil {
				safeCallToolStatus(a.toolStatusCb, ToolEvent{Phase: "start", Name: tc.Name, Input: input})
			}

			// Open a child OTel span for this tool call. The span
			// closes when we set its result attributes below; the ctx
			// carries it down through executeTool so deeper layers can
			// attach events if they want to.
			toolCtx, toolSpan := obs.StartToolCall(ctx, tc.Name, tc.ID, string(input))

			start := time.Now()
			output, toolErr := a.executeTool(toolCtx, tc.Name, tc.Input)
			duration := time.Since(start)

			obs.RecordToolResult(toolSpan, len(output), toolErr)
			toolSpan.End()

			if a.toolStatusCb != nil {
				safeCallToolStatus(a.toolStatusCb, ToolEvent{
					Phase:    "finish",
					Name:     tc.Name,
					Input:    input,
					Duration: duration,
					Output:   output,
					Err:      toolErr,
				})
			}

			// Audit log records the raw, unwrapped output so post-hoc
			// analysis keeps full fidelity — the quarantine wrapping
			// and reflection appends are model-facing concerns, not
			// storage ones.
			if a.auditLog != nil {
				a.auditLog.RecordCtx(ctx, tc.Name, input, output, toolRisk.String(), audit.LevelAction, duration, !toolErr)
			}

			// Circuit breaker (P3-28 second half): record the
			// success or failure for this tool. On a trip, the
			// breaker returns Open=true and the dispatcher prepends a
			// structured <circuit-breaker-open> block to the output
			// so the model sees the escalation cue alongside any
			// reflection / detector / quarantine wrapping that may
			// follow.
			if a.breakerCounter != nil {
				var breakerInput string
				if toolErr {
					breakerInput = output
				}
				if state := a.breakerCounter.Record(tc.Name, breakerInput); state.Open {
					obs.FromCtx(ctx).Warn("circuit_breaker_open",
						"tool", state.Tool,
						"streak", state.Streak,
						"kind", state.LastKind)
					if msg := breaker.EscalationMessage(state); msg != "" {
						output = msg + "\n" + output
					}
				}
			}

			// Reflexion on failure: when a tool errors, invoke the
			// classification-tier reflector (Haiku by default) and
			// append its diagnosis inside a <reflection> block on the
			// tool result. Capped per turn to avoid loops. See
			// reflexion.go.
			if toolErr {
				fn := a.reflectorFn
				if fn == nil {
					fn = a.reflect
				}
				output = maybeAppendReflection(ctx, tc.Name, input, output, &reflectionsThisTurn, fn)
			}

			// Prospective reflection (Batch A): before the tool
			// result leaves the dispatcher, prepend a pre-execution
			// critique for critical-risk tools so the main model
			// sees the classifier's risk assessment alongside the
			// raw output. Advisory — doesn't gate dispatch (that
			// stays with the confirm callback).
			if toolRisk == risk.Critical {
				pfn := a.prospectiveFn
				if pfn == nil {
					pfn = a.prospective
				}
				output = maybeProspectiveReflect(ctx, tc.Name, input, output, &prospectiveThisTurn, pfn)

				// Ensemble voting (P3-33): when the persona has a
				// non-empty consensus list, run prospective once per
				// listed model and prepend a structured
				// <consensus-disagreement> block on disagreement.
				// Pure additive — unanimous panels emit nothing and
				// the existing single-model critique above stays the
				// only escalation signal.
				if p := a.persona; p != nil && len(p.Consensus) > 0 {
					if disagreement := a.runEnsembleProspective(ctx, tc.Name, input, p.Consensus); disagreement != "" {
						output = disagreement + "\n" + output
					}
				}
			}

			// Detector pass (P1-10): run any registered detectors for
			// this tool and append their verdicts to the tool output.
			// Detectors are advisory — a "suspicious" verdict on an
			// otherwise-successful tool surfaces in the model's next
			// turn as a <detector-verdict> block so the main model
			// can decide whether to retry / escalate.
			if !toolErr && a.detectorEngine != nil && a.detectorEngine.HasDetectorsFor(tc.Name) {
				verdicts := a.detectorEngine.EvaluateFor(ctx, tc.Name, string(input), output)
				output = appendDetectorVerdicts(output, verdicts)
			}

			// Quarantine hardware-origin output before it reaches the
			// model. Strips control characters and, for attacker-
			// controllable tools, wraps the result in
			// <untrusted-hardware-output> tags — see quarantine.go.
			quarantined := quarantineOutput(tc.Name, output, toolErr)
			toolResults = append(toolResults, anthropic.NewToolResultBlock(tc.ID, quarantined, toolErr))
		}

		// Flush revisions (P1-14): append each revision as a text block
		// inside the same user message as the tool_results so the
		// model sees both the "tool skipped" signal and the
		// operator's edit in one turn. Each revision renders as a
		// bullet so multi-tool revisions survive cleanly.
		if len(pendingRevisions) > 0 {
			var b strings.Builder
			b.WriteString("The operator has requested revisions instead of running the tool(s) above:\n")
			for _, rev := range pendingRevisions {
				b.WriteString("- ")
				b.WriteString(rev)
				b.WriteString("\n")
			}
			b.WriteString("\nPlease re-plan with these changes.")
			toolResults = append(toolResults, anthropic.NewTextBlock(b.String()))
			pendingRevisions = pendingRevisions[:0]
		}

		a.history = append(a.history, anthropic.NewUserMessage(toolResults...))
		a.compactHistoryLocked()
		a.autoSaveLocked()
	}
}

// streamOnce issues a single streaming Messages request, relays text
// deltas to the caller's TextDelta callback, and returns the fully
// accumulated Message once the stream closes. Request construction
// (including prompt-cache breakpoints on the system prompt and tool
// catalog) lives in buildCachedRequest so cache behaviour can be
// covered by unit tests without an SDK mock.
//
// The main turn is dispatched at the TierPlan cost tier so personas
// that declare a cheaper plan-tier model (e.g. Haiku for read-only
// defenders) pay less without needing bespoke agent plumbing. The
// session fallback — a.model — is used when no persona model is set.
func (a *Agent) streamOnce(ctx context.Context, sysPrompt string, tools []anthropic.ToolUnionParam) (*anthropic.Message, error) {
	model := a.modelForLocked(TierPlan)
	// Extended thinking (Batch A): when the active persona allocates
	// a thinking budget for the plan tier, the model gets room to
	// reason internally before committing to a tool call. Measurably
	// lifts multi-step correctness on agentic tasks. Off by default —
	// personas opt in via their thinking: YAML config.
	thinkingBudget := a.thinkingBudgetForLocked(TierPlan)
	stream := a.client.Messages.NewStreaming(ctx, buildCachedRequestWithThinking(model, sysPrompt, tools, a.history, thinkingBudget))
	defer stream.Close()

	var msg anthropic.Message
	for stream.Next() {
		event := stream.Current()
		if err := msg.Accumulate(event); err != nil {
			return nil, err
		}
		if a.textDeltaCb == nil {
			continue
		}
		if cbd, ok := event.AsAny().(anthropic.ContentBlockDeltaEvent); ok {
			if td, ok := cbd.Delta.AsAny().(anthropic.TextDelta); ok && td.Text != "" {
				safeCallTextDelta(a.textDeltaCb, TextDelta{Text: td.Text})
			}
		}
	}
	if err := stream.Err(); err != nil {
		if a.streamErrCb != nil {
			safeCallStreamErr(a.streamErrCb, err)
		}
		return nil, err
	}
	if a.usageCb != nil {
		safeCallUsage(a.usageCb, Usage{
			InputTokens:         msg.Usage.InputTokens,
			OutputTokens:        msg.Usage.OutputTokens,
			CacheReadTokens:     msg.Usage.CacheReadInputTokens,
			CacheCreationTokens: msg.Usage.CacheCreationInputTokens,
			Model:               model,
		})
	}
	// Stamp usage + finish reason onto the current agent-turn span.
	// trace.SpanFromContext is safe against the noop path — the
	// returned span drops attribute calls when tracing is disabled.
	if span := obs.SpanFromCtx(ctx); span != nil {
		obs.RecordUsage(span,
			msg.Usage.InputTokens,
			msg.Usage.OutputTokens,
			msg.Usage.CacheReadInputTokens,
			msg.Usage.CacheCreationInputTokens,
		)
		if len(msg.StopReason) > 0 {
			obs.RecordFinishReason(span, string(msg.StopReason))
		}
	}
	return &msg, nil
}

func (a *Agent) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.history = nil
}

// deps returns a fully-populated Deps bag so registry-backed handlers
// have access to every facility the agent has. Wired once per dispatch
// call to ensure session-scoped fields (sessionID, snapshotMgr) are
// current.
func (a *Agent) deps() *toolsreg.Deps {
	return &toolsreg.Deps{
		Flipper:         a.flipper,
		Marauder:        a.marauder,
		Bruce:           a.bruce,
		Faultier:        a.faultier,
		BusPirate:       a.buspirate,
		Audit:           a.auditLog,
		Config:          a.cfg,
		Generator:       a.generator,
		GenLLM:          a.genLLM,
		Vision:          a.vision,
		Snapshot:        a.snapshotMgr,
		SessionID:       a.sessionID,
		RAG:             a.ragIndex,
		TargetMem:       a.targetMem,
		WorkflowConfirm: a.workflowConfirmHook,
		BuildVerify:     a.runBuildVerification,
		// Live operator-safety posture for the agent_status diagnostic.
		// Read lock-free at call time so the report is never stale.
		Posture: func() toolsreg.AgentPosture {
			p := ""
			if pa := a.personaAtomic.Load(); pa != nil {
				p = pa.Name
			}
			return toolsreg.AgentPosture{
				ReadOnly:       a.readOnly.Load(),
				Mode:           string(a.Mode()),
				Persona:        p,
				ConfirmRisk:    a.confirmThreshold.String(),
				ConfirmEnabled: a.confirmCb != nil,
			}
		},
	}
}

// RunTool exposes the agent's tool-dispatch path so external
// orchestrators (Campaigns runner, MCP server) can invoke individual
// tools without going through the full Run loop. The two safety
// gates that protect Run are applied here too:
//
//  1. audit.RequireOpen — High/Critical tools are refused when no audit
//     log is wired. Fail-closed: an unattended runner cannot silently
//     execute destructive tools without leaving a trace.
//  2. confirmCb gate — when a confirm callback is installed and the
//     resolved risk meets confirmThreshold, the operator is asked
//     before dispatch. Mirrors the Run-loop gate at agent.go:797.
//
// Outputs are NOT quarantine-wrapped (no <untrusted-hardware-output>
// tags) because RunTool callers consume the result as data, not as
// model context. If you intend to feed RunTool output back to an LLM,
// wrap it through QuarantineForTest / quarantineOutput at the call
// site.
//
// Audit records are written on success and failure exactly as Run
// would record them. ctx cancellation aborts an in-flight tool call.
func (a *Agent) RunTool(ctx context.Context, tool string, params map[string]interface{}) (string, error) {
	if tool == "" {
		return "", fmt.Errorf("agent: empty tool name")
	}
	// turnMu serialises against Run so RunTool doesn't race into a
	// mid-turn confirm gate. mu protects field access inside dispatch.
	a.turnMu.Lock()
	defer a.turnMu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()

	// Resolve risk the same way Run does: prefer the registered
	// Spec.Risk, fall back to risk.Classify when the spec is missing.
	toolRisk := risk.Classify(tool)
	if spec, ok := toolsreg.Get(tool); ok {
		toolRisk = spec.Risk
		if resolved := risk.Classify(tool); resolved > toolRisk {
			toolRisk = resolved
		}
	}

	// Audit gate (fail-closed for High/Critical without audit log).
	if err := audit.RequireOpen(a.auditLog, toolRisk); err != nil {
		return err.Error(), err
	}

	// Confirm gate — same threshold check as the Run loop. RunTool has
	// no approve-all state, so every call gates independently. When no
	// confirmCb is installed (test harnesses, MCP without operator),
	// the gate is skipped — RequireOpen above already blocked
	// High/Critical without audit, so the floor is preserved.
	if a.confirmCb != nil && toolRisk >= a.confirmThreshold {
		rawInput, mErr := json.Marshal(params)
		if mErr != nil {
			// Operator-facing confirm gate must show what's being
			// approved. If params didn't marshal, log it and
			// substitute a placeholder rather than presenting an
			// empty input. Build the placeholder via json.Marshal
			// (not fmt.Sprintf with %q) so a control byte in the
			// error string survives as JSON-valid \u00NN instead
			// of Go-string \a / \v / \xNN — see v0.150.
			obs.Default().Warn("agent_runtool_marshal_failed", "tool", tool, "err", mErr)
			rawInput = marshalErrorPlaceholder(mErr)
		}
		a.mu.Unlock()
		resp := a.confirmWithIdleTimeout(ctx, a.buildConfirmRequest(tool, rawInput, toolRisk))
		a.mu.Lock()
		switch resp.Decision {
		case DecisionDeny, DecisionRevise:
			const denyMsg = "user denied this action"
			if a.auditLog != nil {
				a.auditLog.RecordCtx(ctx, tool, rawInput, denyMsg, toolRisk.String(), audit.LevelAction, 0, false)
			}
			return denyMsg, fmt.Errorf("agent: %s", denyMsg)
		}
	}

	// Marshal params for executeTool's json.RawMessage signature.
	// executeTool re-decodes them but also runs the confidence check
	// and the ToolError-wrapping that RunTool callers benefit from.
	rawInput, err := json.Marshal(params)
	if err != nil {
		return "", fmt.Errorf("agent: marshal params: %w", err)
	}

	start := time.Now()
	output, isErr := a.executeTool(ctx, tool, rawInput)
	duration := time.Since(start)

	if a.auditLog != nil {
		a.auditLog.RecordCtx(ctx, tool, rawInput, output, toolRisk.String(), audit.LevelAction, duration, !isErr)
	}

	if isErr {
		// executeTool wraps errors as ToolError JSON in `output`.
		// Surface it as both the result string and a non-nil error so
		// callers can errors.Is / pattern-match if they want.
		return output, fmt.Errorf("agent: %s tool returned error", tool)
	}
	return output, nil
}

// NewForTest constructs a minimal Agent suitable for the eval
// harness (internal/eval) and cross-package integration tests. No
// Anthropic client, no Flipper — callers wire up whatever the test
// needs. Not part of the stable API; may change without notice.
func NewForTest(model string) *Agent {
	a := &Agent{
		model:            model,
		confirmThreshold: 3, // risk.High
		maxToolsPerTurn:  defaultMaxToolCallsPerTurn,
	}
	return a
}

// HistorySnapshot returns the concatenated user-visible text of the
// agent's current conversation history. Intended for eval / test
// scenarios that want to assert the shape of resumed sessions or
// injected context blocks (e.g. the <handoff-resume> sentinel).
// Not a stable API.
func HistorySnapshot(a *Agent) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var b strings.Builder
	for _, m := range a.history {
		for _, block := range m.Content {
			if block.OfText != nil {
				b.WriteString(block.OfText.Text)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// NewToolErrorForTest exposes the ToolError classifier to cross-
// package test code (internal/eval). Mirrors newToolError. Not a
// stable API.
func NewToolErrorForTest(toolName string, err error, excerpt string) ToolError {
	return newToolError(toolName, err, excerpt)
}

// QuarantineForTest exposes the internal quarantine wrapping helper
// to the eval harness so adversarial scenarios can assert that
// hardware-origin output gets framed as untrusted before reaching
// the main model. Production callers use the unexported
// quarantineOutput directly.
func QuarantineForTest(toolName, output string) string {
	return quarantineOutput(toolName, output, false)
}

// executeTool dispatches a single tool call. On failure the returned
// string is a JSON-encoded ToolError (see toolerror.go) so reflexion
// (P0-05), detectors (P1-10), and report generation can pattern-match
// on the error code and remediation hints. The bool indicates whether
// the returned string represents an error.
func (a *Agent) executeTool(ctx context.Context, name string, input json.RawMessage) (string, bool) {
	var params map[string]interface{}
	if err := json.Unmarshal(input, &params); err != nil {
		te := newToolError(name, fmt.Errorf("parse parameters: %w", err), string(input))
		return te.JSON(), true
	}

	// Batch E — pre-dispatch confidence check. Missing required keys
	// or placeholder values ("TODO", "<fill_in>", empty strings) cause
	// the dispatch to abstain rather than act on shaky arguments. The
	// abstention message is structured so the main loop can iterate
	// (it looks like a tool error without device-state pinning).
	if rep := confidence.Evaluate(params, requiredKeys(name, a.marauder != nil)); rep.ShouldAbstain() {
		te := newToolError(name, fmt.Errorf("low-confidence input — abstaining: %s", rep.Reason), string(input))
		return te.JSON(), true
	}

	result, err := a.dispatch(ctx, name, params)
	if err != nil {
		// Use the dispatch result (if any) as the excerpt — some
		// wrappers return partial output alongside an error.
		te := newToolError(name, err, result)
		// Pin device state at failure time so the report generator
		// (P1-11) and post-hoc debugging have a forensic snapshot.
		// State() uses the 2-second TTL cache so the probe is free
		// when the state oracle already ran this turn.
		if a.flipper != nil {
			if st, err := a.flipper.State(ctx); err == nil && st.Connected {
				te = te.withDeviceState(&st)
			}
		}
		return te.JSON(), true
	}
	return result, false
}

func (a *Agent) dispatch(ctx context.Context, name string, p map[string]interface{}) (output string, err error) {
	// All tools are now in the central registry. The risk gate runs in
	// executeTool (before dispatch is called), so this path inherits the
	// gate for free.
	spec, ok := toolsreg.Get(name)
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}

	// Read-only safety rail (v0.19.0). When engaged, refuse anything
	// above risk.Low. This is the simplification of the persona+mode
	// matrix: a single binary that maps to "is this tool a pure read".
	// Checked before the legacy Mode gate so SetReadOnly takes
	// precedence without callers having to clear opMode first.
	if a.readOnly.Load() && spec.Risk > risk.Low {
		return "", fmt.Errorf(
			"%w: %s is %s-risk; disable read-only to allow",
			ErrReadOnly, spec.Name, spec.Risk)
	}

	// Operation-mode gate (deprecated; v0.20.0 will remove). When the
	// active mode disallows a tool's group, refuse the call before the
	// handler runs. Error wraps ErrBlockedByMode for back-compat with
	// existing errors-Is callers; new code should use ErrReadOnly.
	if m := a.Mode(); !m.Allows(spec.Group) {
		return "", fmt.Errorf("%w: %s blocked in %s mode — %s",
			ErrBlockedByMode, spec.Name, m.DisplayName(), m.Reason(spec.Group))
	}

	// Recover from panics inside the tool handler. With 200+ tools
	// registered any single buggy handler — a nil-deref on an
	// unexpected input shape, a malformed reflection path, an
	// edge-case in a parser — would otherwise crash the whole
	// agent process. The named-return-values pattern lets the
	// deferred recover convert a panic into a tool_error so the
	// LLM sees a structured failure and can react. The recovery
	// log carries a stack trace via runtime/debug so the panic
	// site is visible without GOTRACEBACK=all.
	defer func() {
		if r := recover(); r != nil {
			obs.Default().Error("tool_handler_panicked",
				"tool", name,
				"recovered", fmt.Sprintf("%v", r),
				"stack", string(debug.Stack()))
			output = ""
			err = fmt.Errorf("tool %s panicked: %v", name, r)
		}
	}()

	// Streaming dispatch (P3-28 first half): when the tool opted in
	// AND the host wired a frame callback, run the StreamHandler
	// against a fresh sink and forward frames to the callback in
	// real time. The LLM-facing return string still comes from the
	// handler's final return — partial frames are operator-facing
	// only. Falls through to the regular Handler when the tool
	// didn't opt in or the host didn't install a callback.
	if spec.Streams && spec.StreamHandler != nil && a.toolStreamCb != nil {
		return a.dispatchStreaming(ctx, spec, p)
	}

	return spec.Handler(ctx, a.deps(), p)
}

// dispatchStreaming runs a streaming tool. A consumer goroutine
// drains the sink and forwards frames to the operator-supplied
// callback; the producer is the spec.StreamHandler. The function
// blocks until the handler returns and the consumer drains —
// guarantees that no frames arrive at the callback after dispatch
// returns.
//
// Abort-early: when the callback returns false dispatch calls
// sink.Abort() and cancels the per-call context. The drain loop
// then keeps draining without invoking the callback again so the
// producer's Send calls don't wedge on a full buffer while it
// winds down. Producers honouring abort return their partial
// result via the normal final-string path.
func (a *Agent) dispatchStreaming(ctx context.Context, spec toolsreg.Spec, p map[string]any) (string, error) {
	sink := streaming.NewSink(spec.Name, 0)
	cb := a.toolStreamCb

	streamCtx, cancel := context.WithCancel(ctx)

	done := make(chan struct{})
	go func() {
		defer close(done)
		aborted := false
		for f := range sink.Frames() {
			if aborted {
				continue // drain only — don't invoke callback again
			}
			// safeCallToolStream wraps cb in recover so a panicking
			// host callback (REPL UI / web cockpit disconnect mid-
			// stream) doesn't kill the agent process. A recovered
			// panic is treated as "consumer wants out", same as a
			// `false` return — sink.Abort + ctx cancel fire and
			// the drain continues without re-invoking cb.
			if !safeCallToolStream(cb, f) {
				aborted = true
				sink.Abort()
				cancel()
			}
		}
	}()

	// Defer Close + drain so a panicking StreamHandler can't leak the
	// consumer goroutine. The streaming.Handler contract says handlers
	// MUST defer sink.Close, but trusting every handler author leaves
	// a buggy or new tool one missed defer away from a permanent
	// goroutine stuck on a never-closed Frames() channel. Close is
	// idempotent — well-behaved handlers see this as a redundant
	// second call; misbehaving ones see it as the safety net.
	//
	// Defer order matters: cancel runs first (LIFO), unblocking any
	// producer Send racing the shutdown; then sink.Close fires, which
	// exits the consumer's range loop; then <-done waits so dispatch
	// only returns once the consumer has drained — guarantees no
	// callback runs after dispatch returns.
	defer func() {
		sink.Close()
		<-done
	}()
	defer cancel()

	return spec.StreamHandler(streamCtx, a.deps(), p, sink)
}

// workflowConfirmHook routes a workflow's internal sub-tool
// confirmation request through the same idle-timeout-aware gate as
// the top-level Run dispatch. Called while a.mu is held by Run's
// dispatch loop; releases a.mu for the duration of the prompt to
// avoid wedging field readers on operator idle.
//
// Returns true when the operator approves (or no confirm callback
// is installed — back-compat with test / MCP harnesses), false
// otherwise. The workflow is expected to record the denial as a
// phase result rather than treating it as an error.
func (a *Agent) workflowConfirmHook(ctx context.Context, tool string, input interface{}, riskLevel string) bool {
	if a.confirmCb == nil {
		return true
	}
	// Only gate High/Critical primitives — Low/Medium sub-steps
	// remain silent to avoid confirmation fatigue on pipelines that
	// do dozens of Medium-risk reads per run.
	if !strings.EqualFold(riskLevel, "high") && !strings.EqualFold(riskLevel, "critical") {
		return true
	}
	var level risk.Level
	if strings.EqualFold(riskLevel, "critical") {
		level = risk.Critical
	} else {
		level = risk.High
	}
	// Serialise the input to raw JSON the way the top-level gate
	// shows it — matches what operators already see in the primary
	// confirm prompt and keeps the UX consistent across layers.
	rawInput, mErr := json.Marshal(input)
	if mErr != nil {
		obs.Default().Warn("agent_workflow_confirm_marshal_failed", "tool", tool, "err", mErr)
		rawInput = marshalErrorPlaceholder(mErr)
	}
	a.mu.Unlock()
	resp := a.confirmWithIdleTimeout(ctx, a.buildConfirmRequest(tool, rawInput, level))
	a.mu.Lock()
	return resp.Decision == DecisionApprove || resp.Decision == DecisionApproveAll
}

// buildConfirmRequest assembles the ConfirmRequest the operator UI sees.
// For medium-risk file-write tools (those whose Spec advertises a
// non-nil WriteIntent), it lazily reads the existing file and computes
// a unified diff against the proposed content. The fetch is gated
// behind risk.WantsDiff so it only fires when the prompt is actually
// about to render — there is no Storage Read on every dispatch.
//
// Failures are non-fatal by design: a missing file is treated as an
// empty old side (fresh write), and any other read error is surfaced
// in the Diff field as a one-line warning so the operator can still
// approve. Blocking the confirmation flow on a flaky storage probe
// would be worse UX than letting the operator decide without a
// preview.
func (a *Agent) buildConfirmRequest(tool string, input json.RawMessage, level risk.Level) ConfirmRequest {
	req := ConfirmRequest{Tool: tool, Input: input, Risk: level}

	if !risk.WantsDiff(level) {
		return req
	}
	spec, ok := toolsreg.Get(tool)
	if !ok || spec.WriteIntent == nil {
		return req
	}

	var args map[string]any
	if err := json.Unmarshal(input, &args); err != nil {
		return req
	}
	path, content, want := spec.WriteIntent(args)
	if !want || path == "" {
		return req
	}

	if a.flipper == nil {
		return req
	}

	existing, err := a.flipper.StorageRead(path)
	switch {
	case err == nil:
		req.Diff = diff.Unified(path, stripStorageReadHeader(existing), content)
	case isMissingFileErr(err):
		req.Diff = diff.Unified(path, "", content)
	default:
		req.Diff = unableToFetchMsg(path, err)
	}
	return req
}

// stripStorageReadHeader removes the "Size: N\n" prefix the Flipper's
// storage_read prepends. Without it the diff would show the size
// header as an old line, which is misleading — the operator is
// comparing file bodies, not transport metadata.
func stripStorageReadHeader(out string) string {
	out = strings.TrimLeft(out, "\r\n")
	if idx := strings.Index(out, "\n"); idx >= 0 {
		if strings.HasPrefix(strings.TrimSpace(out[:idx]), "Size:") {
			return out[idx+1:]
		}
	}
	return out
}

// unableToFetchMsg renders the warning the confirmation flow surfaces
// when the existing file couldn't be fetched (and the error wasn't a
// "file does not exist" report). Extracted so a test can pin the exact
// template — the web UI parses this prefix to style the line as a
// warning.
func unableToFetchMsg(path string, err error) string {
	return fmt.Sprintf("(unable to fetch existing file %s: %v)", path, err)
}

// isMissingFileErr returns true when err looks like a "file does not
// exist" report from the Flipper storage transport. The transport
// surfaces this as a plain error string ("File does not exist", "no
// such file"), so we have to string-match — there is no sentinel error
// to unwrap. A false negative just yields the generic warning path,
// which is the safe fallback.
func isMissingFileErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "no such file") ||
		strings.Contains(msg, "not found")
}

// resolveRunPayloadRisk inspects the path argument of a run_payload call and
// returns the name of the underlying operation it will dispatch to along with
// the effective risk level. This mirrors the dispatch logic in runPayload so
// the confirm gate can gate on the real risk before executing anything.
func resolveRunPayloadRisk(path string) (underlyingTool string, level risk.Level) {
	switch {
	case strings.Contains(path, "evil_portal"):
		return "MarauderEvilPortalStart", risk.Critical
	case strings.HasSuffix(path, ".txt") && strings.Contains(path, "badusb"):
		return "BadUSBRun", risk.Critical
	case strings.HasSuffix(path, ".sub"):
		return "SubGHzTx", risk.Critical
	case strings.HasSuffix(path, ".nfc"):
		return "NFCEmulate", risk.High
	case strings.HasSuffix(path, ".ir"):
		return "IRUniversal", risk.Low
	case strings.HasSuffix(path, ".rfid"):
		return "RFIDEmulate", risk.High
	default:
		return "unknown", risk.High
	}
}

// SetRAGIndex installs a custom RAG index. Nil restores the default
// embedded corpus on the next docs_search call.
func (a *Agent) SetRAGIndex(idx *rag.Index) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ragIndex = idx
}

// SetTargetMemory installs the persistent target store. Nil leaves the
// target_* tools inert (dispatch returns a friendly error) — callers
// who failed to open the DB at startup still get a working agent.
func (a *Agent) SetTargetMemory(s *targetmem.Store) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.targetMem = s
}

// mapNFCTypeToDeviceType translates the scanner's Type string into a
// DeviceType value BuildNFC + validateUIDLength will accept. Unknown
// types fall through to "NFC" so the caller can still persist a
// UID-only record. Keep the switch case-insensitive and match on
// substrings — the firmware's exact Type strings vary across forks
// ("Mifare Classic 1K" vs "MIFARE Classic 1K" etc.).
func mapNFCTypeToDeviceType(typ string) string {
	lower := strings.ToLower(typ)
	switch {
	case strings.Contains(lower, "ntag213"):
		return "NTAG213"
	case strings.Contains(lower, "ntag215"):
		return "NTAG215"
	case strings.Contains(lower, "ntag216"):
		return "NTAG216"
	case strings.Contains(lower, "ultralight"):
		return "Mifare Ultralight"
	case strings.Contains(lower, "classic"):
		return "Mifare Classic"
	case strings.Contains(lower, "desfire"):
		return "Mifare DESFire"
	case strings.Contains(lower, "plus"):
		return "Mifare Plus"
	default:
		return "NFC"
	}
}

// sanitizeFilename strips characters that aren't safe in a Flipper SD
// filename. The firmware accepts most ASCII but colons / slashes /
// whitespace cause the on-device browser to render poorly; reduce to
// [0-9A-Za-z_-] for predictability.
func sanitizeFilename(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9',
			r >= 'A' && r <= 'Z',
			r >= 'a' && r <= 'z',
			r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if out == "" {
		return "unknown"
	}
	return out
}

// snapshotEligible returns true when the combination of session
// state, snapshot manager, and path makes this call a candidate
// for an actual Store. Extracted as a predicate so tests can drive
// the decision logic without a real Flipper transport.
func (a *Agent) snapshotEligible(path string) bool {
	return a.snapshotMgr != nil && a.sessionID != "" && path != ""
}

// storeSnapshot writes the given content under the current
// session's snapshot tree. Errors are logged with trace-ID
// propagation via ctx and swallowed — snapshots are advisory.
//
// After each successful Store, Rotate is invoked with the default
// retention to trim the oldest entries if the session has accumulated
// more than snapshot.DefaultRetention undo points. Rotation errors
// degrade to a warning — they never block the write path.
func (a *Agent) storeSnapshot(ctx context.Context, path string, content []byte) {
	if _, err := a.snapshotMgr.Store(a.sessionID, path, content); err != nil {
		obs.FromCtx(ctx).Warn("snapshot_store_failed", "path", path, "err", err)
		return
	}
	if deleted, err := a.snapshotMgr.Rotate(a.sessionID, 0); err != nil {
		obs.FromCtx(ctx).Warn("snapshot_rotate_failed", "err", err)
	} else if deleted > 0 {
		obs.FromCtx(ctx).Info("snapshot_rotated", "deleted", deleted)
	}
}

// subghzBuild is a thin shim retained for the agent-package test wiring
// (internal/agent/wiring_test.go:TestSubghzBuild_BlocksWriteOnHighSeverity).
// The real implementation now lives in internal/tools/build.go; the agent
// reaches it via dispatch → registry → Deps.BuildVerify → runBuildVerification,
// which honours a.verifierFn exactly as the test expects.
func (a *Agent) subghzBuild(ctx context.Context, p map[string]interface{}) (string, error) {
	return a.dispatch(ctx, "subghz_build", p)
}

// marshalErrorPlaceholder builds a JSON-valid {"_marshal_error": ...}
// row when json.Marshal of a tool input fails. Mirrors the v0.150
// audit fix: fmt.Sprintf("%q", err.Error()) is Go-string quoting
// (\a / \v / \xNN for control bytes), not JSON, so a control byte
// in the error message produced an unparseable placeholder. Building
// via json.Marshal guarantees valid escapes (\u00NN) and a fallback
// hardcoded sentinel covers the (effectively impossible) case where
// encoding/json itself rejects the UTF-8 string.
func marshalErrorPlaceholder(err error) []byte {
	if err == nil {
		return []byte(`{"_marshal_error":""}`)
	}
	b, mErr := json.Marshal(map[string]string{"_marshal_error": err.Error()})
	if mErr != nil {
		return []byte(`{"_marshal_error":"unrenderable"}`)
	}
	return b
}

// hasWiFiTool reports whether the filtered tool set still exposes any
// Marauder (wifi_*) capability. Used to decide whether appending the WiFi
// system-prompt addendum makes sense — a read-only persona that has pruned
// every transmit/emulate tool doesn't benefit from WiFi framing.
func hasWiFiTool(tools []anthropic.ToolUnionParam) bool {
	for _, t := range tools {
		if t.OfTool == nil {
			continue
		}
		if strings.HasPrefix(t.OfTool.Name, "wifi_") {
			return true
		}
	}
	return false
}

func toUnionBlocks(blocks []anthropic.ContentBlockUnion) []anthropic.ContentBlockParamUnion {
	var out []anthropic.ContentBlockParamUnion
	for _, b := range blocks {
		switch b.Type {
		case "text":
			out = append(out, anthropic.NewTextBlock(b.Text))
		case "tool_use":
			out = append(out, anthropic.ContentBlockParamUnion{
				OfToolUse: &anthropic.ToolUseBlockParam{
					ID:    b.ID,
					Name:  b.Name,
					Input: b.Input,
				},
			})
		case "thinking":
			// Extended thinking must be echoed back for the model to keep
			// reasoning across turns; dropping it breaks interleaved flows.
			out = append(out, anthropic.NewThinkingBlock(b.Signature, b.Thinking))
		case "redacted_thinking":
			out = append(out, anthropic.NewRedactedThinkingBlock(b.Data))
		default:
			// Unknown block types would otherwise be dropped from history.
			// Surface the surprise on stderr and round-trip the raw JSON as
			// text so context isn't silently lost.
			raw, err := json.Marshal(b)
			if err != nil {
				fmt.Fprintf(os.Stderr, "agent: dropping unknown content block %q (marshal failed: %v)\n", b.Type, err)
				continue
			}
			fmt.Fprintf(os.Stderr, "agent: passing through unknown content block %q\n", b.Type)
			out = append(out, anthropic.NewTextBlock(string(raw)))
		}
	}
	return out
}
