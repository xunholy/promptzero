package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/discover"
	"github.com/xunholy/promptzero/internal/fileformat"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/persona"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/rag"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rules"
	"github.com/xunholy/promptzero/internal/session"
	"github.com/xunholy/promptzero/internal/snapshot"
	"github.com/xunholy/promptzero/internal/validator"
	"github.com/xunholy/promptzero/internal/vision"
	"github.com/xunholy/promptzero/internal/workflows"
)

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
	mu                 sync.Mutex
	client             *anthropic.Client
	flipper            *flipper.Flipper
	marauder           *marauder.Marauder
	cfg                *config.Config
	model              string
	history            []anthropic.MessageParam
	auditLog           *audit.Log
	generator          *generate.Generator
	vision             *vision.Analyzer
	genLLM             provider.Provider
	toolStatusCb       func(ToolEvent)
	textDeltaCb        func(TextDelta)
	usageCb            func(u Usage)
	streamErrCb        func(err error)
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

	// Set up vision analyzer
	a.vision = vision.New(client, cfg.Model)

	return a
}

func (a *Agent) SetMarauder(m *marauder.Marauder)        { a.marauder = m }
func (a *Agent) SetAuditLog(l *audit.Log)                { a.auditLog = l }
func (a *Agent) SetGenerator(g *generate.Generator)      { a.generator = g }
func (a *Agent) SetGenLLM(p provider.Provider)           { a.genLLM = p }
func (a *Agent) SetToolStatusCallback(f func(ToolEvent)) { a.toolStatusCb = f }
func (a *Agent) SetTextDeltaCallback(f func(TextDelta))  { a.textDeltaCb = f }

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
}

// SetUsageCallback registers a per-response token counter. Fires once
// per successful streamOnce with the message's Usage block, including
// prompt-cache read / creation tokens. Pass nil to disable.
func (a *Agent) SetUsageCallback(f func(u Usage)) { a.usageCb = f }

// SetStreamErrorCallback registers a hook that fires when the upstream
// Messages.NewStreaming call returns an error. Wired to the cost
// Tracker so consecutive network failures flip the offline banner.
func (a *Agent) SetStreamErrorCallback(f func(err error)) { a.streamErrCb = f }

// SetConfirmCallback registers an interactive gate consulted before any
// tool whose classified risk meets or exceeds the confirm threshold runs.
// Passing nil disables the gate. Non-interactive surfaces (MCP, web) leave
// this unset so tools execute without prompting.
func (a *Agent) SetConfirmCallback(f ConfirmFunc) { a.confirmCb = f }

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
// {DecisionDeny} and Run proceeds as if the user declined. a.mu
// remains held for the whole wait — Run's contract is that the turn
// is atomic with respect to history mutation — so callers must
// budget for confirmIdleTimeout when the agent can appear wedged
// during operator idle.
//
// The callback receives a cancellable child ctx derived from the caller's
// ctx. It is cancelled on timeout, on parent ctx cancellation, or on a
// successful return — whichever comes first. Callbacks must honour
// ctx.Done() to avoid blocking after the idle deadline fires; the REPL
// implementation already does this.
func (a *Agent) confirmWithIdleTimeout(ctx context.Context, req ConfirmRequest) ConfirmResponse {
	// Snapshot the callback and timeout under the turn-held lock
	// BEFORE spawning the goroutine. Using local copies means a
	// concurrent SetConfirmCallback / SetConfirmIdleTimeout can't
	// race the callback invocation, and the -race detector has no
	// complaint regardless of how callbacks get swapped over a
	// session's lifetime.
	cb := a.confirmCb
	timeout := a.confirmIdleTimeout
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
	// documented on ConfirmFunc.
	go func() { ch <- cb(childCtx, req) }()
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
// ensures the split boundary never separates such a pair: if the first
// tail entry is a user message whose content is all tool_result blocks,
// the window is shifted one entry earlier to keep the preceding assistant
// message with it. If no safe boundary exists within a 4-entry search
// window, compaction is skipped for this call.
func (a *Agent) compactHistoryLocked() {
	if len(a.history) <= maxHistory {
		return
	}
	// Candidate split: keep first 2 + last (maxHistory-2).
	splitIdx := len(a.history) - (maxHistory - 2)
	// Safety search: shift splitIdx earlier if it lands in the middle of a
	// tool_use/tool_result pair (up to 4 positions back).
	for shift := 0; shift <= 4; shift++ {
		idx := splitIdx - shift
		if idx <= 2 {
			// No room to compact without losing the anchor entries.
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
	compacted := make([]anthropic.MessageParam, 2, maxHistory)
	copy(compacted, a.history[:2])
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
	a.mu.Lock()
	defer a.mu.Unlock()

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
	userInput = buildDeviceStateBlock(ctx, a.flipper) + userInput

	a.history = append(a.history, anthropic.NewUserMessage(
		anthropic.NewTextBlock(userInput),
	))

	a.compactHistoryLocked()

	tools := buildTools()
	tools = append(tools, buildGenTools()...)
	tools = append(tools, buildWorkflowTools()...)
	tools = append(tools, buildFileFormatTools()...)
	if a.marauder != nil {
		tools = append(tools, buildMarauderTools()...)
	}
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
		resp, err := a.streamOnce(ctx, sysPrompt, tools)
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
		var approveAllRemaining bool
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
			gated := toolRisk == risk.Critical || !approveAllRemaining
			if a.confirmCb != nil && gated && toolRisk >= a.confirmThreshold {
				resp := a.confirmWithIdleTimeout(ctx, ConfirmRequest{Tool: tc.Name, Input: input, Risk: toolRisk})
				switch resp.Decision {
				case DecisionDeny:
					const denyMsg = "user denied this action"
					if a.toolStatusCb != nil {
						a.toolStatusCb(ToolEvent{Phase: "start", Name: tc.Name, Input: input})
						a.toolStatusCb(ToolEvent{Phase: "finish", Name: tc.Name, Input: input, Output: denyMsg, Err: true})
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
						a.toolStatusCb(ToolEvent{Phase: "start", Name: tc.Name, Input: input})
						a.toolStatusCb(ToolEvent{Phase: "finish", Name: tc.Name, Input: input, Output: resultMsg, Err: true})
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
				}
			}

			if a.toolStatusCb != nil {
				a.toolStatusCb(ToolEvent{Phase: "start", Name: tc.Name, Input: input})
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
				a.toolStatusCb(ToolEvent{
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
				a.textDeltaCb(TextDelta{Text: td.Text})
			}
		}
	}
	if err := stream.Err(); err != nil {
		if a.streamErrCb != nil {
			a.streamErrCb(err)
		}
		return nil, err
	}
	if a.usageCb != nil {
		a.usageCb(Usage{
			InputTokens:         msg.Usage.InputTokens,
			OutputTokens:        msg.Usage.OutputTokens,
			CacheReadTokens:     msg.Usage.CacheReadInputTokens,
			CacheCreationTokens: msg.Usage.CacheCreationInputTokens,
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

func (a *Agent) requireMarauder() error {
	if a.marauder == nil {
		return fmt.Errorf("WiFi devboard not connected — use --wifi flag")
	}
	return nil
}

// RunTool exposes the agent's tool-dispatch path so external
// orchestrators (Campaigns runner, MCP server) can invoke individual
// tools without going through the full Run loop. Honours the risk
// gate, reflexion, detector engine, and quarantine layers exactly
// as Run would — callers get identical semantics to a tool_use
// arriving from the model.
//
// ctx cancellation aborts an in-flight tool call; the returned
// output is whatever the dispatch layer produced (likely the
// ToolError JSON on a ctx-cancel error).
func (a *Agent) RunTool(ctx context.Context, tool string, params map[string]interface{}) (string, error) {
	if tool == "" {
		return "", fmt.Errorf("agent: empty tool name")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.dispatch(ctx, tool, params)
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

func (a *Agent) dispatch(ctx context.Context, name string, p map[string]interface{}) (string, error) {
	switch name {
	// --- Flipper: Sub-GHz ---
	case "subghz_transmit":
		return a.flipper.SubGHzTx(str(p, "file"))
	case "subghz_receive":
		raw, err := a.flipper.SubGHzRx(uint32(intOr(p, "frequency", 0)), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
		if err != nil {
			return raw, err
		}
		// Structured parse (P1-17 follow-up) — the model sees
		// {candidates:[{protocol,frequency,key,bit,te}]} instead of
		// the raw scan transcript.
		parsed := flipper.ParseSubGHzReceive(raw)
		b, _ := json.Marshal(parsed)
		return string(b), nil
	case "subghz_decode":
		return a.flipper.SubGHzDecode(str(p, "file"))
	case "subghz_bruteforce":
		return a.flipper.ExecLong(fmt.Sprintf("subghz bruteforce %s %d", flipper.SanitizeArg(str(p, "file")), intOr(p, "frequency", 0)), time.Duration(intOr(p, "duration_seconds", 60))*time.Second)

	// --- Flipper: IR ---
	case "ir_transmit":
		return a.flipper.IRTxParsed(str(p, "protocol"), str(p, "address"), str(p, "command"))
	case "ir_transmit_raw":
		return a.flipper.IRTxRaw(uint32(intOr(p, "frequency", 38000)), floatOr(p, "duty_cycle", 0.33), str(p, "data"))
	case "ir_receive":
		return a.flipper.IRRx(time.Duration(intOr(p, "timeout_seconds", 30)) * time.Second)
	case "ir_bruteforce":
		return a.flipper.ExecLong(fmt.Sprintf("ir bruteforce %s", flipper.SanitizeArg(str(p, "file"))), time.Duration(intOr(p, "duration_seconds", 60))*time.Second)

	// --- Flipper: NFC ---
	case "nfc_detect":
		raw, err := a.flipper.NFCDetect(time.Duration(intOr(p, "timeout_seconds", 30)) * time.Second)
		if err != nil {
			return raw, err
		}
		parsed := flipper.ParseNFCDetect(raw)
		b, _ := json.Marshal(parsed)
		return string(b), nil
	case "nfc_emulate":
		return a.flipper.NFCEmulate(str(p, "file"))
	case "nfc_subcommand":
		return a.flipper.NFCSubcommand(str(p, "subcommand"), time.Duration(intOr(p, "timeout_seconds", 30))*time.Second)

	// --- Flipper: RFID ---
	case "rfid_read":
		return a.flipper.RFIDRead(ctx, str(p, "mode"), time.Duration(intOr(p, "timeout_seconds", 15))*time.Second)
	case "rfid_emulate":
		return a.flipper.RFIDEmulate(str(p, "protocol"), str(p, "data"), time.Duration(intOr(p, "duration_seconds", 10))*time.Second)
	case "rfid_write":
		return a.flipper.RFIDWrite(str(p, "protocol"), str(p, "data"))

	// --- Flipper: iButton ---
	case "ibutton_read":
		return a.flipper.IButtonRead(time.Duration(intOr(p, "timeout_seconds", 30)) * time.Second)
	case "ibutton_emulate":
		return a.flipper.IButtonEmulate(str(p, "protocol"), str(p, "hex_data"), time.Duration(intOr(p, "duration_seconds", 10))*time.Second)
	case "ibutton_write":
		return a.flipper.IButtonWrite(str(p, "hex_data"))

	// --- Flipper: GPIO ---
	case "gpio_set":
		return a.flipper.GPIOSet(str(p, "pin"), intOr(p, "value", 0))
	case "gpio_read":
		return a.flipper.GPIORead(str(p, "pin"))

	// --- Flipper: BadUSB ---
	case "badusb_run":
		path := str(p, "file")
		if rep, err := a.validateBadUSB(path); err == nil {
			if rep.Severity == validator.SeverityCritical && !a.cfg.Validator.BadUSB.AllowCritical {
				return "", fmt.Errorf("badusb_run blocked by sandbox validator:\n%s\nSet validator.badusb.allow_critical=true to override, or call badusb_validate to triage", rep.RenderText())
			}
			if rep.Severity == validator.SeverityWarn && a.cfg.Validator.BadUSB.WarnAction == "block" {
				return "", fmt.Errorf("badusb_run blocked (warn-action=block):\n%s", rep.RenderText())
			}
		}
		return a.flipper.BadUSBRun(path)
	case "badusb_validate":
		path := str(p, "file")
		rep, err := a.validateBadUSB(path)
		if err != nil {
			return "", err
		}
		out, _ := json.Marshal(rep)
		return string(out), nil

	// --- Flipper: Loader ---
	case "list_apps":
		apps, err := a.flipper.LoaderListParsed()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(apps)
		return string(b), nil
	case "loader_open":
		return a.flipper.LoaderOpen(str(p, "app_name"), str(p, "args"))
	case "loader_close":
		return a.flipper.LoaderClose()

	// --- Flipper: Input ---
	case "input_send":
		return a.flipper.InputSend(str(p, "button"), str(p, "event_type"))

	// --- Flipper: Storage ---
	case "storage_list":
		return a.flipper.StorageList(str(p, "path"))
	case "storage_read":
		return a.flipper.StorageRead(str(p, "path"))
	case "storage_delete":
		return a.flipper.StorageRemove(str(p, "path"))
	case "storage_mkdir":
		return a.flipper.StorageMkdir(str(p, "path"))
	case "storage_info":
		raw, err := a.flipper.StorageStat(str(p, "path"))
		if err != nil {
			return raw, err
		}
		parsed := flipper.ParseStorageStat(raw)
		b, _ := json.Marshal(parsed)
		return string(b), nil

	// --- Flipper: System ---
	case "system_info":
		return a.flipper.DeviceInfo()
	case "power_info":
		return a.flipper.PowerInfo()
	case "device_reboot":
		return a.flipper.Reboot()
	case "flipper_raw_cli":
		return a.flipper.RawCLI(str(p, "command"))
	case "led_set":
		return a.flipper.LED(str(p, "channel"), intOr(p, "value", 0))
	case "vibro":
		return a.flipper.Vibro(boolOr(p, "on", false))
	case "list_devices":
		return a.listDevices()

	// --- Flipper: Sub-GHz (extended) ---
	case "subghz_tx_key":
		return a.flipper.SubGHzTxKey(str(p, "key_hex"), uint32(intOr(p, "frequency", 0)), uint32(intOr(p, "te", 0)), intOr(p, "repeat", 0))
	case "subghz_rx_raw":
		return a.flipper.SubGHzRxRaw(uint32(intOr(p, "frequency", 0)), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
	case "subghz_chat":
		return a.flipper.SubGHzChat(uint32(intOr(p, "frequency", 0)), time.Duration(intOr(p, "duration_seconds", 60))*time.Second)

	// --- Flipper: IR (extended) ---
	case "ir_decode_file":
		return a.flipper.IRDecodeFile(str(p, "path"))
	case "ir_universal_list":
		return a.flipper.IRUniversalList(str(p, "library"))

	// --- Flipper: NFC (extended subshell) ---
	case "nfc_raw_frame":
		return a.flipper.NFCRawFrame(str(p, "hex"), time.Duration(intOr(p, "timeout_seconds", 10))*time.Second)
	case "nfc_apdu":
		return a.flipper.NFCAPDU(str(p, "hex"), time.Duration(intOr(p, "timeout_seconds", 10))*time.Second)
	case "nfc_mfu_rdbl":
		return a.flipper.NFCMFURead(intOr(p, "page", 0), time.Duration(intOr(p, "timeout_seconds", 10))*time.Second)
	case "nfc_mfu_wrbl":
		return a.flipper.NFCMFUWrite(intOr(p, "page", 0), str(p, "hex"), time.Duration(intOr(p, "timeout_seconds", 10))*time.Second)
	case "nfc_dump_protocol":
		return a.flipper.NFCDumpProtocol(str(p, "protocol"), time.Duration(intOr(p, "timeout_seconds", 30))*time.Second)
	case "loader_nfc_magic":
		return a.flipper.LoaderNFCMagic()
	case "loader_mfkey":
		return a.flipper.LoaderMFKey()
	case "loader_mifare_nested":
		return a.flipper.LoaderMifareNested()
	case "loader_picopass":
		return a.flipper.LoaderPicopass()
	case "loader_seader":
		return a.flipper.LoaderSeader()

	// --- Flipper: RFID (extended) ---
	case "rfid_raw_read":
		return a.flipper.RFIDRawRead(str(p, "mode"), str(p, "file"), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
	case "rfid_raw_analyze":
		return a.flipper.RFIDRawAnalyze(str(p, "file"))
	case "rfid_raw_emulate":
		return a.flipper.RFIDRawEmulate(str(p, "file"), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
	case "loader_t5577_multiwriter":
		return a.flipper.LoaderT5577MultiWriter()

	// --- Flipper: OneWire / iButton ---
	case "onewire_search":
		return a.flipper.OneWireSearch(time.Duration(intOr(p, "duration_seconds", 10)) * time.Second)

	// --- Flipper: GPIO / hardware recon ---
	case "i2c_scan":
		return a.flipper.I2CScan()

	// --- Flipper: Scripting ---
	case "js_run":
		return a.flipper.JSRun(str(p, "path"), time.Duration(intOr(p, "duration_seconds", 60))*time.Second)

	// --- Flipper: Storage (extended) ---
	case "storage_copy":
		// Snapshot the destination (if it already exists) before the
		// copy so /rewind can restore it — the source stays intact by
		// definition and doesn't need a snapshot.
		a.snapshotBeforeWrite(ctx, str(p, "dst"))
		return a.flipper.StorageCopy(str(p, "src"), str(p, "dst"))
	case "storage_rename":
		// Snapshot both ends: the destination might pre-exist (will
		// be clobbered) and so might the source (rename removes it
		// from its original path, so the user may want it back).
		a.snapshotBeforeWrite(ctx, str(p, "src"))
		a.snapshotBeforeWrite(ctx, str(p, "dst"))
		return a.flipper.StorageRename(str(p, "src"), str(p, "dst"))
	case "storage_md5":
		return a.flipper.StorageMD5(str(p, "path"))
	case "storage_tree":
		return a.flipper.StorageTree(str(p, "path"))

	// --- Flipper: Loader FAP shortcuts (Sub-GHz / misc) ---
	case "loader_subghz_bruteforcer":
		return a.flipper.LoaderSubGHzBruteforcer()
	case "loader_subghz_playlist":
		return a.flipper.LoaderSubGHzPlaylist()
	case "loader_protoview":
		return a.flipper.LoaderProtoView()
	case "loader_spectrum_analyzer":
		return a.flipper.LoaderSpectrumAnalyzer()
	case "loader_signal_generator":
		return a.flipper.LoaderSignalGenerator()
	case "loader_nrf24mousejacker":
		return a.flipper.LoaderNRF24Mousejacker()
	case "loader_uart_terminal":
		return a.flipper.LoaderUARTTerminal()
	case "loader_spi_mem_manager":
		return a.flipper.LoaderSPIMemManager()
	case "loader_unitemp":
		return a.flipper.LoaderUnitemp()

	// --- Flipper: System (extended) ---
	case "loader_info":
		return a.flipper.LoaderInfo()
	case "loader_signal":
		return a.flipper.LoaderSignal(intOr(p, "signal", 0), str(p, "arg_hex"))
	case "log_stream":
		return a.flipper.LogStream(time.Duration(intOr(p, "duration_seconds", 15))*time.Second, str(p, "level"))
	case "power_reboot_dfu":
		return a.flipper.PowerRebootDFU()
	case "update_install":
		return a.flipper.UpdateInstall(str(p, "manifest"))
	case "crypto_store_key":
		return a.flipper.CryptoStoreKey(intOr(p, "slot", 0), str(p, "key_type"), intOr(p, "key_size", 128), str(p, "hex"))
	case "bt_hci_info":
		return a.flipper.BTHCIInfo()

	// --- Generation Pipeline ---
	case "generate_evil_portal":
		return a.generatePayloadWithBypass(ctx, "evil_portal", str(p, "description"), str(p, "path"), str(p, "target_os"), boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
	case "generate_badusb":
		return a.generatePayloadWithBypass(ctx, "badusb", str(p, "description"), str(p, "path"), str(p, "target_os"), boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
	case "generate_subghz":
		return a.generatePayloadWithBypass(ctx, "subghz", str(p, "description"), str(p, "path"), "", boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
	case "generate_ir":
		return a.generatePayloadWithBypass(ctx, "ir", str(p, "description"), str(p, "path"), "", boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
	case "generate_nfc":
		return a.generatePayloadWithBypass(ctx, "nfc", str(p, "description"), str(p, "path"), "", boolOr(p, "deploy", true), boolOr(p, "verify_bypass", false))
	case "run_payload":
		return a.runPayload(str(p, "path"), str(p, "command"))
	case "generate_deploy_run":
		return a.generateDeployRun(ctx, str(p, "type"), str(p, "description"), str(p, "path"), str(p, "target_os"))

	// --- Vision ---
	case "analyze_image":
		return a.analyzeImage(ctx, str(p, "image"), str(p, "question"))

	// --- Discovery ---
	case "discover_apps":
		return a.discoverApps()

	// --- Audit ---
	case "audit_query":
		return a.auditQuery(intOr(p, "limit", 20))
	case "audit_export":
		return a.auditExport()
	case "audit_stats":
		return a.auditStats()

	// --- RAG / docs retrieval (Batch D) ---
	case "docs_search":
		return a.docsSearch(str(p, "query"), intOr(p, "k", 5))

	// --- Parametric file builders (P1-13) ---
	case "subghz_bruteforce_generate":
		return a.subghzBruteforceGenerate(ctx, p)
	case "subghz_build":
		return a.subghzBuild(ctx, p)
	case "rfid_build":
		return a.rfidBuild(ctx, p)
	case "ir_build":
		return a.irBuild(ctx, p)
	case "nfc_build":
		return a.nfcBuild(ctx, p)

	// --- File-format editors ---
	case "fileformat_read":
		return a.fileformatRead(str(p, "path"))
	case "fileformat_edit":
		return a.fileformatEdit(ctx, str(p, "path"), p["edits"], str(p, "output_path"))
	case "fileformat_diff":
		return a.fileformatDiff(str(p, "path_a"), str(p, "path_b"))

	// --- Composite Workflows ---
	case "workflow_nfc_badge_pipeline":
		return workflows.NFCBadgePipeline(ctx, a.workflowDeps(), p)
	case "workflow_wifi_target_to_hashcat":
		return workflows.WiFiTargetToHashcat(ctx, a.workflowDeps(), p)
	case "workflow_garage_door_triage":
		return workflows.GarageDoorTriage(ctx, a.workflowDeps(), p)
	case "workflow_rolljam_lab_demo":
		return workflows.RolljamLabDemo(ctx, a.workflowDeps(), p)
	case "workflow_phys_pentest_badge_walk":
		return workflows.PhysPentestBadgeWalk(ctx, a.workflowDeps(), p)
	case "workflow_hw_recon_blackbox_device":
		return workflows.HWReconBlackbox(ctx, a.workflowDeps(), p)
	case "workflow_badusb_target_profile":
		return workflows.BadUSBTargetProfile(ctx, a.workflowDeps(), p)

	// --- Marauder WiFi ---
	case "wifi_scan_ap":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		// Structured parse (P1-17) so the model sees {aps: [...]},
		// not a prose table. Falls back to the raw text automatically
		// when the parser can't extract rows — ScanResult.RawLines
		// carries anything it couldn't classify.
		res, err := a.marauder.ScanAPParsed(time.Duration(intOr(p, "duration_seconds", 15)) * time.Second)
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(res)
		return string(b), nil
	case "wifi_scan_all":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.ScanAll(time.Duration(intOr(p, "duration_seconds", 15)) * time.Second)
	case "wifi_stop_scan":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.StopScan()
	case "wifi_select_ap":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SelectAP(str(p, "indices"))
	case "wifi_select_station":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SelectStation(str(p, "indices"))
	case "wifi_select_ssid":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SelectSSID(str(p, "indices"))
	case "wifi_list_aps":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		res, err := a.marauder.ListAPsParsed()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(res)
		return string(b), nil
	case "wifi_list_ssids":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.ListSSIDs()
	case "wifi_list_stations":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		res, err := a.marauder.ListStationsParsed()
		if err != nil {
			return "", err
		}
		b, _ := json.Marshal(res)
		return string(b), nil
	case "wifi_clear_aps":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.ClearAPs()
	case "wifi_clear_ssids":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.ClearSSIDs()
	case "wifi_clear_stations":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.ClearStations()
	case "wifi_deauth":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.DeauthAttack(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_deauth_station_list":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.DeauthToStationList(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_beacon_spam":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.BeaconSpamList(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_beacon_random":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.BeaconSpamRandom(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_beacon_clone":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.BeaconSpamClone(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_beacon_rickroll":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.BeaconSpamRickroll(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_beacon_funny":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.BeaconSpamFunny(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_probe_flood":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.ProbeFlood(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_csa_attack":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.CSAAttack(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_sae_flood":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SAEFlood(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_sniff_pmkid":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffPMKID(intOr(p, "channel", 0), boolOr(p, "deauth", false), boolOr(p, "list_only", false), time.Duration(intOr(p, "duration_seconds", 60))*time.Second)
	case "wifi_sniff_beacon":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffBeacon(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_sniff_deauth":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffDeauth(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_sniff_probe":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffProbe(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_sniff_pwnagotchi":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffPwnagotchi(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_sniff_raw":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffRaw(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_ble_spam":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.BLESpam(str(p, "mode"), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
	case "wifi_sniff_bt":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffBT(str(p, "target_type"), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
	case "wifi_sniff_skimmer":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SniffSkimmer(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_evil_portal_start":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.EvilPortalStart(str(p, "filename"))
	case "wifi_evil_portal_stop":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.StopScan()
	case "wifi_add_ssid":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.AddSSID(str(p, "name"))
	case "wifi_remove_ssid":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.RemoveSSID(intOr(p, "index", 0))
	case "wifi_generate_ssids":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.GenerateSSIDs(intOr(p, "count", 10))
	case "wifi_join":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.Join(intOr(p, "ap_index", 0), str(p, "password"))
	case "wifi_ping_scan":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.PingScan(time.Duration(intOr(p, "duration_seconds", 30)) * time.Second)
	case "wifi_arp_scan":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.ARPScan(time.Duration(intOr(p, "duration_seconds", 15)) * time.Second)
	case "wifi_port_scan":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.PortScan(intOr(p, "ip_index", 0), time.Duration(intOr(p, "duration_seconds", 30))*time.Second)
	case "wifi_random_mac":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.RandomAPMAC()
	case "wifi_clone_mac":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.CloneAPMAC(intOr(p, "ap_index", 0))
	case "wifi_save_aps":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SaveAPs()
	case "wifi_save_ssids":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SaveSSIDs()
	case "wifi_load_aps":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.LoadAPs()
	case "wifi_load_ssids":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.LoadSSIDs()
	case "wifi_settings":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.Settings()
	case "wifi_set_setting":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SetSetting(str(p, "name"), str(p, "value"))
	case "wifi_set_channel":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.SetChannel(intOr(p, "channel", 1))
	case "wifi_info":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.Info()
	case "wifi_reboot":
		if err := a.requireMarauder(); err != nil {
			return "", err
		}
		return a.marauder.Reboot()

	default:
		return "", fmt.Errorf("unknown tool: %s", name)
	}
}

// workflowDeps snapshots the agent's current component wiring into the
// dependency surface composite workflows operate over. Built per-call so
// late SetMarauder / SetGenerator / SetAuditLog updates are picked up.
func (a *Agent) workflowDeps() workflows.Deps {
	var caps flipper.Capabilities
	if a.flipper != nil {
		caps = a.flipper.Capabilities()
	}
	return workflows.Deps{
		Flipper:      a.flipper,
		Marauder:     a.marauder,
		Vision:       a.vision,
		Audit:        a.auditLog,
		Generator:    a.generator,
		GenLLM:       a.genLLM,
		Capabilities: caps,
	}
}

// --- Generation Pipeline Handlers ---

func (a *Agent) generatePayload(ctx context.Context, payloadType, description, path, targetOS string, deploy bool) (string, error) {
	return a.generatePayloadWithBypass(ctx, payloadType, description, path, targetOS, deploy, false)
}

// generatePayloadWithBypass is the internal entry point that honours
// the chain-of-verification (P1-16): after a generate_* call succeeds,
// a classification-tier verifier analyses the content for known
// failure modes. Severity high / critical blocks the deploy step
// unless bypass is true — the operator can override via the tool's
// verify_bypass param when they intentionally want to ship a risky
// payload.
func (a *Agent) generatePayloadWithBypass(ctx context.Context, payloadType, description, path, targetOS string, deploy, bypass bool) (string, error) {
	if a.generator == nil {
		return "", fmt.Errorf("generator not configured — set a generation LLM provider")
	}

	var result *generate.Result
	var err error

	switch payloadType {
	case "evil_portal":
		result, err = a.generator.EvilPortal(ctx, description)
	case "badusb":
		result, err = a.generator.BadUSB(ctx, description, targetOS)
	case "subghz":
		result, err = a.generator.SubGHz(ctx, description)
	case "ir":
		result, err = a.generator.IR(ctx, description)
	case "nfc":
		result, err = a.generator.NFC(ctx, description)
	default:
		return "", fmt.Errorf("unknown payload type: %s", payloadType)
	}

	if err != nil {
		return "", err
	}

	// Chain-of-verification: Haiku pass against the generated content
	// before deploy. Errors degrade to an uncertified verdict — they
	// never block generation.
	fn := a.verifierFn
	if fn == nil {
		fn = a.verifyPayload
	}
	verdict, _ := fn(ctx, payloadType, result.Content)
	summary := verdictSummary(verdict)

	if deploy && shouldBlockDeploy(verdict, bypass) {
		return fmt.Sprintf("Generated %s but deploy blocked by verifier.\n\n%s\n\nPreview:\n%s\n\nPass verify_bypass=true to override if you accept the risk.",
			payloadType, summary, result.Preview), nil
	}

	if deploy {
		// Snapshot the destination path before deploying so /rewind
		// can roll back a bad evil-portal / BadUSB / subghz overwrite.
		// The resolved path is the caller-supplied value or the
		// generator's default; the snapshot hook handles the not-yet-
		// exists case silently.
		deployPath := path
		if deployPath == "" {
			deployPath = defaultGeneratePath(payloadType)
		}
		a.snapshotBeforeWrite(ctx, deployPath)

		deployCtx, deployCancel := context.WithTimeout(ctx, 30*time.Second)
		deployErr := a.generator.Deploy(deployCtx, result, path)
		deployCancel()
		if deployErr != nil {
			return "", fmt.Errorf("generated %s but deploy failed: %w\n\n%s\n\nContent preview:\n%s", payloadType, deployErr, summary, result.Preview)
		}
		return fmt.Sprintf("Generated and deployed %s to %s\n\n%s\n\nPreview:\n%s", payloadType, result.Path, summary, result.Preview), nil
	}

	return fmt.Sprintf("Generated %s (not deployed)\n\n%s\n\nPreview:\n%s", payloadType, summary, result.Preview), nil
}

func (a *Agent) runPayload(path, command string) (string, error) {
	switch {
	case strings.Contains(path, "evil_portal"):
		if a.marauder != nil {
			return a.marauder.EvilPortalStart("")
		}
		return "", fmt.Errorf("evil portal requires WiFi devboard (--wifi)")
	case strings.HasSuffix(path, ".txt") && strings.Contains(path, "badusb"):
		return a.flipper.BadUSBRun(path)
	case strings.HasSuffix(path, ".sub"):
		return a.flipper.SubGHzTx(path)
	case strings.HasSuffix(path, ".ir"):
		if command == "" {
			command = "Power" // default
		}
		// IR files are transmitted via the universal remote; use IRUniversal with path as remote name.
		return a.flipper.IRUniversal(path, command)
	case strings.HasSuffix(path, ".nfc"):
		return a.flipper.NFCEmulate(path)
	case strings.HasSuffix(path, ".rfid"):
		return a.flipper.LoaderOpen("RFID", path)
	default:
		return "", fmt.Errorf("unknown payload type for path: %s", path)
	}
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

func (a *Agent) generateDeployRun(ctx context.Context, payloadType, description, path, targetOS string) (string, error) {
	// Generate + deploy
	genResult, err := a.generatePayload(ctx, payloadType, description, path, targetOS, true)
	if err != nil {
		return "", err
	}

	// Determine the deployed path
	deployedPath := path
	if deployedPath == "" {
		switch payloadType {
		case "evil_portal":
			deployedPath = "/ext/apps_data/evil_portal/index.html"
		case "badusb":
			deployedPath = "/ext/badusb/generated_payload.txt"
		case "subghz":
			deployedPath = "/ext/subghz/generated_signal.sub"
		case "ir":
			deployedPath = "/ext/infrared/generated_remote.ir"
		case "nfc":
			deployedPath = "/ext/nfc/generated_tag.nfc"
		}
	}

	// Run
	runResult, err := a.runPayload(deployedPath, "")
	if err != nil {
		return genResult + fmt.Sprintf("\n\nGenerated and deployed, but run failed: %v", err), nil
	}

	return genResult + "\n\nExecuted: " + runResult, nil
}

// --- Vision Handler ---

func (a *Agent) analyzeImage(ctx context.Context, image, question string) (string, error) {
	if a.vision == nil {
		return "", fmt.Errorf("vision not available")
	}

	// Route to base64 handler if the data URI prefix is present, or if the
	// string has no path separator and no file extension dot (i.e. it looks
	// like raw base64 rather than a filesystem path).
	if strings.HasPrefix(image, "data:") || (!strings.HasPrefix(image, "/") && !strings.Contains(image, ".")) {
		return a.vision.AnalyzeBase64(ctx, image, question)
	}
	return a.vision.AnalyzeFile(ctx, image, question)
}

// --- Discovery Handler ---

func (a *Agent) discoverApps() (string, error) {
	apps, err := discover.ScanApps(a.flipper)
	if err != nil {
		return "", err
	}
	return discover.FormatApps(apps), nil
}

// --- Audit Handlers ---

func (a *Agent) auditQuery(limit int) (string, error) {
	if a.auditLog == nil {
		return "Audit logging not enabled", nil
	}
	entries, err := a.auditLog.Query(limit)
	if err != nil {
		return "", err
	}
	data, _ := json.MarshalIndent(entries, "", "  ")
	return string(data), nil
}

func (a *Agent) auditExport() (string, error) {
	if a.auditLog == nil {
		return "Audit logging not enabled", nil
	}
	return a.auditLog.Export()
}

func (a *Agent) auditStats() (string, error) {
	if a.auditLog == nil {
		return "Audit logging not enabled", nil
	}
	return a.auditLog.Stats()
}

// --- RAG / Docs Retrieval (Batch D) ---

// docsSearch runs a BM25 query over the bundled documentation corpus
// and returns the top-K ranked snippets. The index lazily initialises
// on first call using the default embedded corpus; SetRAGIndex lets
// callers inject a custom index (tests, plugins with extra docs).
func (a *Agent) docsSearch(query string, k int) (string, error) {
	if query == "" {
		return "", fmt.Errorf("query required")
	}
	if k <= 0 {
		k = 5
	}
	if k > 20 {
		k = 20
	}
	a.mu.Lock()
	if a.ragIndex == nil {
		a.ragIndex = rag.DefaultIndex()
	}
	idx := a.ragIndex
	a.mu.Unlock()
	hits := idx.Search(query, k)
	if len(hits) == 0 {
		return fmt.Sprintf("no results for %q", query), nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d results for %q:\n", len(hits), query)
	for _, h := range hits {
		fmt.Fprintf(&b, "\n## %s (%s) — score %.2f\n%s\n", h.Doc.Title, h.Doc.Source, h.Score, rag.Snippet(h.Doc.Body, query, 400))
	}
	return b.String(), nil
}

// SetRAGIndex installs a custom RAG index. Nil restores the default
// embedded corpus on the next docs_search call.
func (a *Agent) SetRAGIndex(idx *rag.Index) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ragIndex = idx
}

// --- Device Registry ---

func (a *Agent) listDevices() (string, error) {
	if len(a.cfg.Devices) == 0 {
		return "No devices configured. Add devices to config.yaml.", nil
	}
	var out string
	for name, dev := range a.cfg.Devices {
		out += fmt.Sprintf("- %s (type: %s, file: %s)\n", name, dev.Type, dev.File)
		for cmd, signal := range dev.Commands {
			out += fmt.Sprintf("    command: %s -> %s\n", cmd, signal)
		}
	}
	return out, nil
}

// --- File-format Handlers ---

// validateBadUSB reads the script off the Flipper SD card and runs it
// through the BadUSB sandbox validator. Returns the Report or an error
// if the file can't be read. The enabled check is honored here so the
// caller can branch on "validator disabled" without duplicating the
// config lookup.
func (a *Agent) validateBadUSB(path string) (validator.Report, error) {
	if path == "" {
		return validator.Report{}, fmt.Errorf("path required")
	}
	// Enabled *bool is tri-state: nil = default on, false = explicit off.
	if en := a.cfg.Validator.BadUSB.Enabled; en != nil && !*en {
		return validator.Report{Name: path}, nil
	}
	raw, err := a.flipper.StorageRead(path)
	if err != nil {
		return validator.Report{}, fmt.Errorf("storage read %s: %w", path, err)
	}
	return validator.Validate(path, raw), nil
}

// fileformatRead pulls a Flipper capture via storage_read, parses it, and
// returns structural JSON so the LLM sees named fields rather than one
// giant string. The wrapper envelope ({path, format, file}) keeps the
// format tag at the top level so the model can pivot without parsing the
// body.
func (a *Agent) fileformatRead(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	raw, err := a.flipper.StorageRead(path)
	if err != nil {
		return "", fmt.Errorf("storage read %s: %w", path, err)
	}
	model, format, err := fileformat.LoadFile(path, []byte(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	envelope := map[string]interface{}{
		"path":   path,
		"format": string(format),
		"file":   model,
	}
	b, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// fileformatEdit reads + parses, applies the top-level edits map, then
// serializes + writes. outputPath defaults to the input path so callers can
// edit-in-place without specifying it. Unknown edit keys return an error
// from the format-specific applier rather than silently no-op'ing.
func (a *Agent) fileformatEdit(ctx context.Context, path string, editsIn interface{}, outputPath string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	edits, ok := editsIn.(map[string]interface{})
	if !ok || len(edits) == 0 {
		return "", fmt.Errorf("edits must be a non-empty object")
	}
	raw, err := a.flipper.StorageRead(path)
	if err != nil {
		return "", fmt.Errorf("storage read %s: %w", path, err)
	}
	model, format, err := fileformat.LoadFile(path, []byte(raw))
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	if err := fileformat.ApplyEdits(format, model, edits); err != nil {
		return "", fmt.Errorf("apply edits: %w", err)
	}
	out, err := fileformat.SaveFile(format, model)
	if err != nil {
		return "", fmt.Errorf("serialize: %w", err)
	}
	target := outputPath
	if target == "" {
		target = path
	}
	// Snapshot the existing file (best-effort) before we overwrite it
	// so /rewind can restore. When target != path the source file is
	// preserved implicitly; we still snapshot target so an out-of-place
	// edit onto an existing file is undoable.
	a.snapshotBeforeWrite(ctx, target)
	if err := a.flipper.WriteFileCtx(ctx, target, out); err != nil {
		return "", fmt.Errorf("write %s: %w", target, err)
	}
	return fmt.Sprintf("edited %s (format=%s, %d bytes) → %s", path, format, len(out), target), nil
}

// defaultGeneratePath mirrors the generator package's default-path
// selection so the agent can snapshot the eventual deploy target
// before handing off to Deploy. Keeping a parallel implementation
// here avoids a circular dep on internal/generate and is one
// switch — easy to maintain in lockstep with generator.defaultPath.
func defaultGeneratePath(payloadType string) string {
	switch payloadType {
	case "evil_portal":
		return "/ext/apps_data/evil_portal/index.html"
	case "badusb":
		return "/ext/badusb/generated_payload.txt"
	case "subghz":
		return "/ext/subghz/generated_signal.sub"
	case "ir":
		return "/ext/infrared/generated_remote.ir"
	case "nfc":
		return "/ext/nfc/generated_tag.nfc"
	}
	return ""
}

// snapshotBeforeWrite reads the current content of path off the
// Flipper and records it under the active session's snapshot tree.
// Best-effort: storage_read failures (file doesn't exist yet,
// transport hiccup) are swallowed — /rewind is a convenience, not
// load-bearing, and a failed snapshot must never block the write.
// No-op when the snapshot manager or session id is unset.
//
// Accepts the caller's ctx so the warn log carries the turn's trace
// ID — snapshot I/O should be visible in the same Jaeger/Tempo trace
// as the tool call that triggered it.
func (a *Agent) snapshotBeforeWrite(ctx context.Context, path string) {
	if !a.snapshotEligible(path) {
		return
	}
	raw, err := a.flipper.StorageRead(path)
	if err != nil {
		// Target doesn't exist yet (fresh write) — nothing to snapshot.
		return
	}
	a.storeSnapshot(ctx, path, []byte(raw))
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
func (a *Agent) storeSnapshot(ctx context.Context, path string, content []byte) {
	if _, err := a.snapshotMgr.Store(a.sessionID, path, content); err != nil {
		obs.FromCtx(ctx).Warn("snapshot_store_failed", "path", path, "err", err)
	}
}

// subghzBruteforceGenerate synthesises a RAW .sub file that sweeps a
// key range at Princeton-style OOK timing and writes it to the SD
// card. Useful for replaying a small sweep against a target the
// operator hasn't been able to capture. See
// fileformat.BuildSubBruteforce for the encoding details.
func (a *Agent) subghzBruteforceGenerate(ctx context.Context, p map[string]interface{}) (string, error) {
	path := str(p, "path")
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	// Cache the params as locals so the success-message key count
	// uses the same values that went into the file (avoids a drift
	// risk where a future intOr refactor returns different values on
	// successive calls).
	startKey := uint64(intOr(p, "start_key", 0))
	endKey := uint64(intOr(p, "end_key", 0))
	bitCount := intOr(p, "bit_count", 0)

	raw, err := fileformat.BuildSubBruteforce(fileformat.SubBruteforceParams{
		Frequency: uint32(intOr(p, "frequency", 0)),
		BitCount:  bitCount,
		StartKey:  startKey,
		EndKey:    endKey,
		TE:        intOr(p, "te", 0),
		Preset:    str(p, "preset"),
	})
	if err != nil {
		return "", err
	}
	a.snapshotBeforeWrite(ctx, path)
	if err := a.flipper.WriteFileCtx(ctx, path, raw); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	count := endKey - startKey + 1
	return fmt.Sprintf("built %d-byte bruteforce .sub (%d keys × %d bits) → %s",
		len(raw), count, bitCount, path), nil
}

// subghzBuild synthesises a .sub file from operator parameters and
// writes it to the SD card via WriteFileCtx. See fileformat.BuildSub
// for the validation rules — invalid freq / key surfaces back to the
// caller as a clean error, never a half-written file (the snapshot
// hook still runs if the path pre-existed).
func (a *Agent) subghzBuild(ctx context.Context, p map[string]interface{}) (string, error) {
	path := str(p, "path")
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	raw, err := fileformat.BuildSub(fileformat.SubBuildParams{
		Frequency: uint32(intOr(p, "frequency", 0)),
		Protocol:  str(p, "protocol"),
		Preset:    str(p, "preset"),
		Key:       str(p, "key_hex"),
		Bit:       intOr(p, "bit", 0),
		TE:        intOr(p, "te", 0),
	})
	if err != nil {
		return "", err
	}
	summary, blockMsg := a.runBuildVerification(ctx, "subghz", raw, boolOr(p, "verify_bypass", false))
	if blockMsg != "" {
		return blockMsg, nil
	}
	a.snapshotBeforeWrite(ctx, path)
	if err := a.flipper.WriteFileCtx(ctx, path, raw); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return fmt.Sprintf("built %d-byte .sub → %s\n%s", len(raw), path, summary), nil
}

// rfidBuild synthesises a .rfid file for LF badge cloning.
func (a *Agent) rfidBuild(ctx context.Context, p map[string]interface{}) (string, error) {
	path := str(p, "path")
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	raw, err := fileformat.BuildRFID(fileformat.RFIDBuildParams{
		KeyType: str(p, "key_type"),
		Data:    str(p, "data"),
	})
	if err != nil {
		return "", err
	}
	summary, blockMsg := a.runBuildVerification(ctx, "rfid", raw, boolOr(p, "verify_bypass", false))
	if blockMsg != "" {
		return blockMsg, nil
	}
	a.snapshotBeforeWrite(ctx, path)
	if err := a.flipper.WriteFileCtx(ctx, path, raw); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return fmt.Sprintf("built %d-byte .rfid → %s\n%s", len(raw), path, summary), nil
}

// irBuild synthesises a .ir universal-remote file from an array of
// signals. Accepts the LLM's loose JSON shape (nested interface{}
// values from the top-level map) and coerces into typed IRSignals.
func (a *Agent) irBuild(ctx context.Context, p map[string]interface{}) (string, error) {
	path := str(p, "path")
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	rawSignals, ok := p["signals"].([]interface{})
	if !ok || len(rawSignals) == 0 {
		return "", fmt.Errorf("signals must be a non-empty array")
	}
	signals := make([]fileformat.IRSignal, 0, len(rawSignals))
	for i, rs := range rawSignals {
		m, ok := rs.(map[string]interface{})
		if !ok {
			return "", fmt.Errorf("signals[%d] must be an object", i)
		}
		sig := fileformat.IRSignal{
			Name:      str(m, "name"),
			Type:      str(m, "type"),
			Protocol:  str(m, "protocol"),
			Address:   str(m, "address"),
			Command:   str(m, "command"),
			Frequency: intOr(m, "frequency", 0),
			DutyCycle: floatOr(m, "duty_cycle", 0),
		}
		if arr, ok := m["data"].([]interface{}); ok {
			sig.Data = make([]int, 0, len(arr))
			for _, v := range arr {
				if f, ok := v.(float64); ok {
					sig.Data = append(sig.Data, int(f))
				}
			}
		}
		signals = append(signals, sig)
	}
	raw, err := fileformat.BuildIR(fileformat.IRBuildParams{
		Name:    str(p, "name"),
		Signals: signals,
	})
	if err != nil {
		return "", err
	}
	summary, blockMsg := a.runBuildVerification(ctx, "ir", raw, boolOr(p, "verify_bypass", false))
	if blockMsg != "" {
		return blockMsg, nil
	}
	a.snapshotBeforeWrite(ctx, path)
	if err := a.flipper.WriteFileCtx(ctx, path, raw); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return fmt.Sprintf("built %d-byte .ir (%d signals) → %s\n%s", len(raw), len(signals), path, summary), nil
}

// nfcBuild synthesises a .nfc file. Blocks is a map<string,string>
// in the LLM JSON shape (integer keys become string keys); we parse
// them back into ints.
func (a *Agent) nfcBuild(ctx context.Context, p map[string]interface{}) (string, error) {
	path := str(p, "path")
	if path == "" {
		return "", fmt.Errorf("path required")
	}
	params := fileformat.NFCBuildParams{
		DeviceType: str(p, "device_type"),
		UID:        str(p, "uid"),
		ATQA:       str(p, "atqa"),
		SAK:        str(p, "sak"),
		MifareType: str(p, "mifare_type"),
		Blocks:     map[int]string{},
	}
	if blocks, ok := p["blocks"].(map[string]interface{}); ok {
		for k, v := range blocks {
			idx, err := strconv.Atoi(k)
			if err != nil {
				return "", fmt.Errorf("blocks key %q must be an integer", k)
			}
			if hex, ok := v.(string); ok {
				params.Blocks[idx] = hex
			}
		}
	}
	raw, err := fileformat.BuildNFC(params)
	if err != nil {
		return "", err
	}
	summary, blockMsg := a.runBuildVerification(ctx, "nfc", raw, boolOr(p, "verify_bypass", false))
	if blockMsg != "" {
		return blockMsg, nil
	}
	a.snapshotBeforeWrite(ctx, path)
	if err := a.flipper.WriteFileCtx(ctx, path, raw); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return fmt.Sprintf("built %d-byte .nfc → %s\n%s", len(raw), path, summary), nil
}

// fileformatDiff reads + parses two paths and returns the per-field diff
// as JSON. Format mismatches surface as same_format=false, empty entries.
func (a *Agent) fileformatDiff(pathA, pathB string) (string, error) {
	if pathA == "" || pathB == "" {
		return "", fmt.Errorf("path_a and path_b are both required")
	}
	rawA, err := a.flipper.StorageRead(pathA)
	if err != nil {
		return "", fmt.Errorf("storage read %s: %w", pathA, err)
	}
	rawB, err := a.flipper.StorageRead(pathB)
	if err != nil {
		return "", fmt.Errorf("storage read %s: %w", pathB, err)
	}
	modelA, formatA, err := fileformat.LoadFile(pathA, []byte(rawA))
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", pathA, err)
	}
	modelB, formatB, err := fileformat.LoadFile(pathB, []byte(rawB))
	if err != nil {
		return "", fmt.Errorf("parse %s: %w", pathB, err)
	}
	result, err := fileformat.Diff(formatA, modelA, formatB, modelB)
	if err != nil {
		return "", err
	}
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// --- Helpers ---

func str(p map[string]interface{}, key string) string {
	if v, ok := p[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func intOr(p map[string]interface{}, key string, fallback int) int {
	if v, ok := p[key]; ok {
		switch n := v.(type) {
		case float64:
			return int(n)
		case string:
			if i, err := strconv.Atoi(n); err == nil {
				return i
			}
		}
	}
	return fallback
}

func floatOr(p map[string]interface{}, key string, fallback float64) float64 {
	if v, ok := p[key]; ok {
		if f, ok := v.(float64); ok {
			return f
		}
	}
	return fallback
}

func boolOr(p map[string]interface{}, key string, fallback bool) bool {
	if v, ok := p[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return fallback
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
