// Package tools is the single source of truth for every tool PromptZero
// exposes to an LLM (via internal/agent) and to MCP clients (via
// internal/mcp). Adding a tool means writing one [Spec] and calling
// [Register] from a package init — the agent dispatch switch and the
// MCP s.add() side are then generated automatically from the registry.
//
// Before this package existed, every tool lived in three places:
//   - internal/mcp/server.go: s.add(name, desc, opts, required, handler)
//   - internal/agent/tools.go: tool(name, desc, props, required...)
//   - internal/agent/agent.go: case "name": return <handler logic>
//
// Drift between those layers caused real user-facing bugs (device_info
// vs system_info naming drift; storage_write registered in MCP but
// undispatched in the agent; nfc_dump_protocol sending the wrong
// protocol token to Momentum). See docs/refactor/registry-migration.md
// for the cross-wave runbook.
package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/xunholy/promptzero/internal/audit"
	"github.com/xunholy/promptzero/internal/bruce"
	"github.com/xunholy/promptzero/internal/buspirate"
	"github.com/xunholy/promptzero/internal/config"
	"github.com/xunholy/promptzero/internal/faultier"
	"github.com/xunholy/promptzero/internal/flipper"
	"github.com/xunholy/promptzero/internal/generate"
	"github.com/xunholy/promptzero/internal/marauder"
	"github.com/xunholy/promptzero/internal/provider"
	"github.com/xunholy/promptzero/internal/rag"
	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/snapshot"
	"github.com/xunholy/promptzero/internal/targetmem"
	"github.com/xunholy/promptzero/internal/vision"
)

// Group classifies a tool for the per-turn router (internal/agent/router.go).
// The string values MUST stay in sync with the Group* constants in that file
// so narrowTools can resolve a tool to its group purely from its [Spec].
type Group string

// Group* constants mirror the values in internal/agent/router.go. They are
// duplicated here (rather than imported) so this package stays leaf-like —
// internal/agent depends on internal/tools, not the other way round.
const (
	GroupMetaAudit      Group = "meta.audit"
	GroupMetaUtil       Group = "meta.util"
	GroupFlipperSystem  Group = "flipper.system"
	GroupFlipperSubGHz  Group = "flipper.rf.subghz"
	GroupFlipperIR      Group = "flipper.rf.ir"
	GroupFlipperNFC     Group = "flipper.nfc"
	GroupFlipperRFID    Group = "flipper.rfid"
	GroupFlipperIButton Group = "flipper.ibutton"
	GroupFlipperBadUSB  Group = "flipper.badusb"
	GroupFlipperHW      Group = "flipper.hw"
	GroupMarauderWiFi   Group = "marauder.wifi"
	GroupGen            Group = "gen"
	GroupWorkflows      Group = "workflows"
	GroupVision         Group = "vision"

	// GroupSecurity covers host-side security tools (hash analysis,
	// network scanning, HTTP enumeration). Single group for v0.5; may
	// be split into per-family subgroups (GroupSecurityHash,
	// GroupSecurityRecon, etc.) in v0.6 if the tool count grows past ~10.
	GroupSecurity Group = "security"

	// GroupHostTools covers tools that run on the operator's host machine
	// rather than on Flipper-attached hardware — firmware extraction,
	// container-bridge tools, binary analysis utilities.
	GroupHostTools Group = "host.tools"
)

// Handler is the single unified tool handler signature. Ctx is the turn
// context (already carrying trace IDs, OTel span, etc. in agent mode).
// The Deps bag is injected by whichever mode hosts the registry; the
// handler MUST guard against nil fields that its mode may not wire up
// (e.g. an MCP-only host will not set Snapshot or Generator).
type Handler func(ctx context.Context, d *Deps, args map[string]any) (string, error)

// Spec is the canonical description of one tool.
//
// A Spec is self-contained: Name + Description + Schema + Required are the
// contract that the MCP server advertises and the Anthropic schema
// declares; Risk + Group drive confirmation gates and the per-turn
// router; Handler is the code that runs when the tool is invoked; and
// AgentOnly / Aliases adapt the same Spec to the two host modes.
type Spec struct {
	// Name is the canonical tool identifier. Must be unique across the
	// entire registry — [Register] panics on a duplicate (an init-time
	// loud failure is the right shape for a programming error that
	// would silently corrupt dispatch otherwise).
	Name string

	// Aliases are additional names that resolve to the same Handler.
	// Used for legacy synonyms — e.g. system_info was the agent-side
	// name and device_info is the MCP / firmware name. Both resolve
	// via [Get]. Aliases MUST NOT collide with another Spec's Name.
	Aliases []string

	// Description is the user-visible tool documentation. Must be
	// self-contained — the MCP client, the agent's Anthropic schema,
	// and /tools all read this same string. Keep it under ~1 KB so
	// the prompt-cache breakpoint stays reasonable.
	Description string

	// Schema is the canonical JSON Schema for the tool's parameters
	// (an object with "properties" and optionally "required"). Both
	// mode adapters decode arguments into map[string]any, so the
	// schema's job is catalog advertisement, not runtime validation.
	Schema json.RawMessage

	// Required lists parameters the caller MUST supply. The MCP mode
	// adapter validates this explicitly (missingRequired in the old
	// s.add()); the agent mode advertises it via InputSchema.Required.
	Required []string

	// Risk is the confirmation-gate classification. Drives
	// internal/risk.Classify, the MCP annotation hints
	// (readOnlyHint/destructiveHint/openWorldHint), and the interactive
	// ConfirmFunc prompt in REPL mode.
	Risk risk.Level

	// Group is the router bucket. Defaults to GroupMetaUtil when the
	// zero value is registered. See internal/agent/router.go for the
	// narrowing logic.
	Group Group

	// AgentOnly excludes this tool from the MCP adapter. Reserved for
	// LLM-composition tools that require facilities MCP does not have
	// (generator LLM, vision analyzer, snapshot manager, workflow
	// confirmation hook). An AgentOnly handler may safely dereference
	// any field on Deps; a non-AgentOnly handler must degrade when
	// those fields are nil.
	AgentOnly bool

	// Handler is the dispatch body. Wave engineers paste the
	// corresponding `case "<name>":` body from internal/agent/agent.go's
	// dispatch switch into this function, substituting `a.flipper` →
	// `d.Flipper`, `a.marauder` → `d.Marauder`, etc.
	Handler Handler

	// WriteIntent, when non-nil, is invoked by the confirmation flow
	// to extract the (path, content) the tool would write. The flow
	// uses these to fetch the existing file and show a unified diff
	// in the confirmation prompt before the operator approves a
	// medium-risk overwrite. nil means "this tool isn't a file write"
	// — the vast majority of Specs.
	//
	// The function MUST be cheap and side-effect-free: it runs at
	// confirmation time, on the args the model proposed, before any
	// risk gate has cleared. Returning ok=false signals "args don't
	// describe a write right now" and the framework skips the diff
	// preview without erroring (e.g. a deploy=false flag).
	WriteIntent func(args map[string]any) (path string, content string, ok bool)
}

// Deps is the dependency bag both host modes inject when invoking a
// [Handler]. Fields are pointers so a nil zero value is a valid
// "feature disabled" signal; handlers MUST tolerate nil for any
// feature their mode does not wire up.
//
// MCP mode (internal/mcp) wires only the first four — Flipper, Marauder,
// Audit, Config. The LLM-specific fields (Generator, GenLLM, Vision,
// Snapshot, RAG, TargetMem, SessionID, WorkflowConfirm) stay nil, and
// AgentOnly handlers are the only ones allowed to dereference them.
//
// Agent mode (internal/agent) wires every field from the running
// *Agent instance.
type Deps struct {
	// --- Always wired ---

	// Flipper is the serial transport + capability bag for the
	// connected Flipper Zero. Nil only in degenerate test setups that
	// do not touch hardware; production handlers may assume non-nil.
	Flipper *flipper.Flipper

	// Marauder is the optional ESP32 Marauder devboard. Nil when the
	// operator did not start PromptZero with --wifi (or the MCP
	// NewServer was called with m==nil). WiFi handlers MUST
	// short-circuit on a nil Marauder — the agent's requireMarauder()
	// helper does this in the current code; handlers can call a
	// similar helper on Deps.
	Marauder *marauder.Marauder

	// Bruce is the optional Bruce ESP32 devboard (https://github.com/pr3y/Bruce).
	// Nil when the operator has not configured a Bruce device (bruce.port
	// absent in config, or --bruce flag not supplied). Bruce handlers MUST
	// short-circuit on a nil Bruce — call [Deps.RequireBruce] at the top
	// of every handler, mirroring the [Deps.RequireMarauder] pattern.
	Bruce *bruce.Client

	// Faultier is the optional hextreeio Faultier USB voltage-glitcher.
	// Nil when no faultier.port is configured. Glitch handlers MUST
	// short-circuit on a nil Faultier — call [Deps.RequireFaultier]
	// at the top of each handler.
	Faultier *faultier.Client

	// BusPirate is the optional Bus Pirate 5 universal-bus probe.
	// Nil when no buspirate.port is configured. BusPirate handlers
	// MUST short-circuit on nil — call [Deps.RequireBusPirate] at
	// the top of each handler.
	BusPirate *buspirate.Client

	// Audit is the session audit log. Nil means "audit disabled" —
	// handlers that write to the log should no-op in that case. The
	// audit_* tools surface this with a friendly string.
	Audit *audit.Log

	// Config is the running process's resolved configuration — used
	// by badusb_run to consult Validator.BadUSB.AllowCritical, by
	// anything that resolves paths, etc. Nil is a bug.
	Config *config.Config

	// --- Agent-only (LLM facilities) ---

	// Generator drives the generate_* tools (evil_portal, badusb,
	// subghz, ir, nfc). Nil means no generation LLM is configured;
	// the handlers return a friendly "generator not configured" error.
	Generator *generate.Generator

	// GenLLM is the underlying provider the generator uses. Some
	// workflow handlers call it directly for ad-hoc synthesis that
	// doesn't fit the generator's typed payload shape.
	GenLLM provider.Provider

	// Vision drives analyze_image. Nil means vision is not configured.
	Vision *vision.Analyzer

	// Snapshot stores pre-write copies of Flipper SD files so /rewind
	// can roll back. Nil disables snapshots (Store is skipped). Tools
	// that clobber SD content (storage_copy, storage_rename,
	// storage_write, fileformat_edit, *_build, generate_*) must call
	// [Deps.SnapshotBeforeWrite] before writing.
	Snapshot *snapshot.Manager

	// SessionID is the active session's identifier. Paired with
	// Snapshot — [Deps.SnapshotBeforeWrite] is a no-op when this is
	// empty (off-session tests, MCP mode) even if Snapshot is non-nil.
	SessionID string

	// RAG is the lexical index for docs_search. Nil falls back to the
	// embedded index on first call (the existing behaviour in
	// internal/agent/agent.go:docsSearch).
	RAG *rag.Index

	// TargetMem is the persistent target-facts store (internal/targetmem).
	// Nil means target_* tools return the "targets feature not
	// enabled" friendly message.
	TargetMem *targetmem.Store

	// WorkflowConfirm is the operator-confirmation hook for workflow
	// sub-tools. Nil means "auto-approve every sub-step" (the MCP and
	// test defaults). The returned bool indicates approval.
	WorkflowConfirm func(ctx context.Context, tool string, input any, riskLevel string) bool

	// BuildVerify runs the chain-of-verification LLM pass on freshly-built
	// file bytes and returns (summary, blockMsg). A non-empty blockMsg means
	// the caller MUST NOT persist the file — surface it as the tool result.
	// An empty blockMsg and non-empty summary means the write can proceed;
	// append the summary to the success message.
	//
	// Nil means skip verification (MCP mode, test setups without a live LLM
	// client). Handlers for *_build and generate_* tools call
	// [Deps.RunBuildVerification] which handles the nil guard, so direct
	// nil checks are not needed in individual handlers.
	BuildVerify func(ctx context.Context, payloadType string, content []byte, bypass bool) (summary, blockMsg string)
}

// SnapshotBeforeWrite captures a pre-write copy of path's existing
// content (if any) into the per-session snapshot tree, so /rewind can
// roll the write back. A no-op when the snapshot feature is disabled
// (nil manager, empty session ID, or empty path). Errors are swallowed
// — snapshots are advisory and must never block the write path.
//
// Wave engineers migrating storage_copy / storage_rename /
// fileformat_edit / *_build / generate_* handlers MUST call this before
// the underlying write, mirroring the existing agent.snapshotBeforeWrite
// behaviour. An identical helper kept the diff smaller in the
// agent-side migration.
func (d *Deps) SnapshotBeforeWrite(ctx context.Context, path string) {
	if d == nil || d.Snapshot == nil || d.SessionID == "" || path == "" {
		return
	}
	if d.Flipper == nil {
		return
	}
	raw, err := d.Flipper.StorageRead(path)
	if err != nil {
		// Target doesn't exist yet — fresh write, nothing to capture.
		return
	}
	// Errors are swallowed by design — see agent.storeSnapshot for
	// the logging-via-obs counterpart used in agent mode.
	_, _ = d.Snapshot.Store(d.SessionID, path, []byte(raw))
}

// --- Registry ---

// registry is the process-wide tool registry. Guarded by regMu so
// Register / All / Get are safe for concurrent access, even though the
// only production pattern is "populate from init() funcs, then read".
var (
	regMu   sync.RWMutex
	byName  = map[string]Spec{}   // canonical name → Spec
	byAlias = map[string]string{} // alias → canonical name
	order   []string              // registration order (stable enumeration)
)

// Register adds a Spec to the registry. Panics on duplicate Name or
// Alias — a collision is a programming error that would silently
// corrupt dispatch, so we fail loudly at init.
func Register(s Spec) {
	if s.Name == "" {
		panic("tools.Register: Spec.Name is empty")
	}
	if s.Handler == nil {
		panic(fmt.Sprintf("tools.Register: %q has nil Handler", s.Name))
	}

	regMu.Lock()
	defer regMu.Unlock()

	if _, dup := byName[s.Name]; dup {
		panic(fmt.Sprintf("tools.Register: duplicate tool name %q", s.Name))
	}
	if existing, dup := byAlias[s.Name]; dup {
		panic(fmt.Sprintf("tools.Register: name %q collides with alias already bound to %q", s.Name, existing))
	}
	for _, a := range s.Aliases {
		if a == "" {
			panic(fmt.Sprintf("tools.Register: %q has an empty alias", s.Name))
		}
		if a == s.Name {
			panic(fmt.Sprintf("tools.Register: %q lists itself as an alias", s.Name))
		}
		if _, dup := byName[a]; dup {
			panic(fmt.Sprintf("tools.Register: alias %q on %q collides with registered tool", a, s.Name))
		}
		if prev, dup := byAlias[a]; dup {
			panic(fmt.Sprintf("tools.Register: alias %q on %q already bound to %q", a, s.Name, prev))
		}
	}

	byName[s.Name] = s
	for _, a := range s.Aliases {
		byAlias[a] = s.Name
	}
	order = append(order, s.Name)
}

// All returns every registered Spec in registration order. The slice
// is a fresh copy — callers may sort or filter in place without
// affecting the registry.
func All() []Spec {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Spec, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out
}

// Get returns the Spec registered under name or any of its aliases,
// and whether the lookup succeeded.
func Get(name string) (Spec, bool) {
	regMu.RLock()
	defer regMu.RUnlock()
	if s, ok := byName[name]; ok {
		return s, true
	}
	if canonical, ok := byAlias[name]; ok {
		return byName[canonical], true
	}
	return Spec{}, false
}

// Names returns every registered name AND alias, sorted. Intended for
// tests, /tools listings, and audit/report generation — production
// dispatch should iterate [All] so registration order is preserved.
func Names() []string {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]string, 0, len(byName)+len(byAlias))
	for n := range byName {
		out = append(out, n)
	}
	for a := range byAlias {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// resetForTest clears the registry and registers a cleanup with t to
// restore the original (post-init) registry when the test (and any
// subtests) finish. This makes the reset safe to combine with
// `-count=N`: each test sees a freshly-empty registry, but
// subsequent tests in the same process — and re-runs of the same
// test — get the production registrations back.
//
// Package-private so tests within this package can exercise Register
// without leaking state between cases. Production code has no reason
// to reach for this.
func resetForTest(t interface {
	Helper()
	Cleanup(func())
}) {
	t.Helper()
	regMu.Lock()
	snapByName := make(map[string]Spec, len(byName))
	for k, v := range byName {
		snapByName[k] = v
	}
	snapByAlias := make(map[string]string, len(byAlias))
	for k, v := range byAlias {
		snapByAlias[k] = v
	}
	snapOrder := append([]string(nil), order...)
	byName = map[string]Spec{}
	byAlias = map[string]string{}
	order = nil
	regMu.Unlock()
	t.Cleanup(func() {
		regMu.Lock()
		defer regMu.Unlock()
		byName = snapByName
		byAlias = snapByAlias
		order = snapOrder
	})
}

// UnregisterForTest removes a single tool (and its aliases) from the
// registry. Exported so sibling-package tests (e.g. internal/agent)
// can register a one-shot fake tool with t.Cleanup(...) and avoid
// leaking it across re-runs (`go test -count=N`). Production code
// has no reason to reach for this — the registry is intended to be
// init-time-immutable after all package init()s have completed.
//
// No-op if name is unregistered, so cleanup paths can call it
// unconditionally.
func UnregisterForTest(name string) {
	regMu.Lock()
	defer regMu.Unlock()
	spec, ok := byName[name]
	if !ok {
		return
	}
	delete(byName, name)
	for _, a := range spec.Aliases {
		delete(byAlias, a)
	}
	for i, n := range order {
		if n == name {
			order = append(order[:i], order[i+1:]...)
			break
		}
	}
}

// RequireMarauder returns a friendly error when the optional Marauder
// devboard is not connected. WiFi and Marauder handlers call this
// before invoking any d.Marauder method, mirroring the agent's
// requireMarauder() shape (internal/agent/agent.go:870).
func (d *Deps) RequireMarauder() error {
	if d == nil || d.Marauder == nil {
		return fmt.Errorf("WiFi devboard not connected — use --wifi flag")
	}
	return nil
}

// RunBuildVerification calls BuildVerify if wired, or returns empty
// strings when the verifier is not available (MCP mode, tests). A
// convenience wrapper so individual *_build handlers do not need to
// nil-check BuildVerify themselves.
func (d *Deps) RunBuildVerification(ctx context.Context, payloadType string, content []byte, bypass bool) (summary, blockMsg string) {
	if d == nil || d.BuildVerify == nil {
		return "", ""
	}
	return d.BuildVerify(ctx, payloadType, content, bypass)
}
