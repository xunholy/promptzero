package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/xunholy/promptzero/internal/attack"
	"github.com/xunholy/promptzero/internal/confidence"
	"github.com/xunholy/promptzero/internal/obs"
	"github.com/xunholy/promptzero/internal/tools"
)

// routerTimeout caps the tool-group narrower's Haiku call. The router
// must finish before any tool runs — a hung call delays every turn
// it triggers on. Three seconds is enough for the JSON-only response
// shape; on timeout we degrade to "no narrowing" (full catalog
// returned) — same fail-open posture as reflect / prospective /
// verify.
const routerTimeout = 3 * time.Second

// Tool groups are the coarse-grained buckets the router reasons over.
// Each tool in the agent catalog maps to exactly one group via
// ToolGroup. Groups named meta.* are always sent to the main model,
// regardless of the user's apparent intent — they hold audit primitives,
// general utilities, and structured format tools the agent may need
// for any task.
const (
	GroupMetaAudit      = "meta.audit"     // always on
	GroupMetaUtil       = "meta.util"      // always on
	GroupFlipperSystem  = "flipper.system" // storage, loader, power, etc.
	GroupFlipperSubGHz  = "flipper.rf.subghz"
	GroupFlipperIR      = "flipper.rf.ir"
	GroupFlipperNFC     = "flipper.nfc"
	GroupFlipperRFID    = "flipper.rfid"
	GroupFlipperIButton = "flipper.ibutton"
	GroupFlipperBadUSB  = "flipper.badusb"
	GroupFlipperHW      = "flipper.hw" // GPIO / I2C / OneWire
	GroupMarauderWiFi   = "marauder.wifi"
	GroupGen            = "gen"
	GroupWorkflows      = "workflows"
	GroupVision         = "vision"
	// GroupSecurity covers host-side security tools (hash analysis,
	// network scanning, HTTP enumeration). Mirrors the constant of the
	// same name in internal/tools/spec.go.
	GroupSecurity = "security"
	// GroupHostTools covers tools that run on the operator's host machine
	// (firmware extraction, container-bridge tools, binary analysis).
	GroupHostTools = "host.tools"
)

// alwaysOnGroups names groups that the router is never allowed to
// drop. Losing audit queries or list_devices mid-turn would make the
// agent incapable of answering "what happened?" or "what's here?" even
// when the user's latest question is about RF work.
var alwaysOnGroups = map[string]bool{
	GroupMetaAudit: true,
	GroupMetaUtil:  true,
}

// ToolGroup returns the logical group a registered tool belongs to.
// The registered Spec.Group is the source of truth — Mode.Allows()
// (persona blocking) and the dynamic router's narrowing both consult
// the same value, so they cannot disagree.
//
// For names not in the registry (or specs that left Group at the zero
// value), the function falls through to a name-prefix heuristic so a
// tool registered without an explicit Group still classifies. Tools
// that match neither path map to GroupMetaUtil, which is the safe
// default — shipping them every turn never breaks correctness.
func ToolGroup(name string) string {
	if spec, ok := tools.Get(name); ok && spec.Group != "" {
		return string(spec.Group)
	}
	switch {
	case strings.HasPrefix(name, "audit_"):
		return GroupMetaAudit
	case name == "list_devices", name == "discover_apps", strings.HasPrefix(name, "fileformat_"):
		return GroupMetaUtil
	case strings.HasPrefix(name, "subghz_"):
		return GroupFlipperSubGHz
	case strings.HasPrefix(name, "ir_"):
		return GroupFlipperIR
	case strings.HasPrefix(name, "nfc_"):
		return GroupFlipperNFC
	case strings.HasPrefix(name, "rfid_"):
		return GroupFlipperRFID
	case strings.HasPrefix(name, "ibutton_"):
		return GroupFlipperIButton
	case strings.HasPrefix(name, "badusb_"):
		return GroupFlipperBadUSB
	case strings.HasPrefix(name, "gpio_"), name == "i2c_scan", strings.HasPrefix(name, "onewire_"):
		return GroupFlipperHW
	case strings.HasPrefix(name, "wifi_"):
		return GroupMarauderWiFi
	case strings.HasPrefix(name, "generate_"), name == "run_payload", name == "generate_deploy_run":
		return GroupGen
	case strings.HasPrefix(name, "workflow_"):
		return GroupWorkflows
	case name == "analyze_image":
		return GroupVision
	case name == "hash_identify",
		name == "hash_crack_dictionary",
		name == "port_scan_tcp",
		name == "http_enum_common":
		return GroupSecurity
	case name == "firmware_extract":
		return GroupHostTools
	case strings.HasPrefix(name, "loader_"),
		strings.HasPrefix(name, "storage_"),
		name == "list_apps",
		name == "flipper_raw_cli",
		name == "device_reboot",
		name == "system_info",
		name == "device_info",
		name == "power_info",
		name == "led_set",
		name == "vibro",
		name == "log_stream",
		name == "js_run",
		name == "input_send",
		name == "bt_hci_info",
		name == "update_install",
		name == "power_reboot_dfu",
		name == "crypto_store_key":
		return GroupFlipperSystem
	default:
		return GroupMetaUtil
	}
}

// minNarrowedTools is the lower bound below which narrowing refuses to
// trim the catalog further — if the router's picks leave the agent
// with fewer than this many tools, we revert to the full set. Guards
// against a miscalibrated router silently crippling a session. Three
// is low enough that legitimate narrow queries ("summarise the audit
// log") still benefit from the trim but a router that hallucinates
// one irrelevant group can't render the agent mute.
const minNarrowedTools = 3

// routerFunc is the external router signature: given the user's input
// and the set of groups currently available in the catalog, return
// the set the main model should see. Returning nil / an error causes
// narrowTools to fall back to the full catalog — "correctness over
// cost" is the dominant principle here.
type routerFunc func(ctx context.Context, userInput string, available map[string]bool) (selected map[string]bool, err error)

// narrowTools filters allTools down to those belonging to a group the
// router selected (plus alwaysOnGroups). Three early-return bail-outs
// send the full catalog through unchanged:
//  1. router is nil (feature disabled)
//  2. router errored or returned empty
//  3. the narrowed set would be smaller than minNarrowedTools
//
// The intent is that a broken or uncertain router can never break a
// session — worst case we pay full input-token cost for that turn.
func narrowTools(
	ctx context.Context,
	userInput string,
	allTools []anthropic.ToolUnionParam,
	router routerFunc,
) []anthropic.ToolUnionParam {
	if router == nil {
		return allTools
	}

	available := make(map[string]bool, 16)
	for _, t := range allTools {
		if t.OfTool == nil {
			continue
		}
		available[ToolGroup(t.OfTool.Name)] = true
	}

	selected, err := router(ctx, userInput, available)
	if err != nil || len(selected) == 0 {
		return allTools
	}

	out := make([]anthropic.ToolUnionParam, 0, len(allTools))
	for _, t := range allTools {
		if t.OfTool == nil {
			// Tools with no concrete body (future union variants) pass
			// through unchanged — we can't group them.
			out = append(out, t)
			continue
		}
		g := ToolGroup(t.OfTool.Name)
		if alwaysOnGroups[g] || selected[g] {
			out = append(out, t)
		}
	}

	if len(out) < minNarrowedTools {
		return allTools
	}
	return out
}

// routeGroups is the production router: a single classification-tier
// call (Haiku by default) that asks the model which groups are relevant
// to the user's turn. Requires a live Anthropic client; for unit tests
// inject a synchronous routerFunc into Agent.routerFn instead.
//
// Concurrency contract: the caller MUST hold a.mu. routeGroups reads
// a.persona (via modelForLocked) and a.client without re-locking — it
// only ever runs from inside Run() today, which holds the mutex for
// the full turn. If this ever gets called from a different path,
// promote to ModelFor (the public, mutex-acquiring wrapper).
func (a *Agent) routeGroups(ctx context.Context, userInput string, available map[string]bool) (map[string]bool, error) {
	if len(available) == 0 {
		return nil, nil
	}
	groups := make([]string, 0, len(available))
	for g := range available {
		groups = append(groups, g)
	}
	sort.Strings(groups) // deterministic for caching + debuggability

	system := "You are a fast tool-group router for PromptZero, an AI hardware operator. " +
		"Given the user's turn, decide which tool groups (from the provided list) hold tools the agent will need. " +
		"Be generous — include adjacent groups if the user's intent spans them — but exclude groups clearly unrelated. " +
		"Respond with a JSON object: {\"groups\": [<names>], \"confidence\": <0.0-1.0>}. " +
		"Set confidence near 1.0 when the intent is unambiguous; ≤0.5 when you are guessing. " +
		"For backward compatibility a bare JSON array (no confidence) is also accepted — " +
		"prefer the object form so the agent can fall back to the full catalog when you are unsure. " +
		"Output ONLY JSON. No prose, no markdown fences.\n\n" +
		"Available groups: " + strings.Join(groups, ", ")

	model := a.modelForLocked(TierClassify)
	callCtx, cancel := context.WithTimeout(ctx, routerTimeout)
	defer cancel()
	resp, err := a.client.Messages.New(callCtx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 128,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(userInput))},
	})
	if err != nil {
		// Loud on timeout — a stalled router means EVERY subsequent
		// turn pays the timeout before falling back to the full catalog.
		// Quiet on other errors per the pattern in reflect/prospective.
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			obs.FromCtx(ctx).Warn("router_timeout",
				"model", model,
				"timeout", routerTimeout.String())
		}
		return nil, fmt.Errorf("router: %w", err)
	}
	a.fireTierUsage(model, resp.Usage)

	var text string
	for _, b := range resp.Content {
		if b.Type == "text" {
			text += b.Text
		}
	}
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, nil
	}

	// Extract confidence first; abstaining beats guessing on a
	// catalog narrow. ParseClassifierResponse returns score=1.0
	// when the model returned the legacy bare-array form, so old
	// behaviour is preserved.
	score, hasSignal := confidence.ParseClassifierResponse(text)
	if hasSignal {
		threshold := a.routerConfidenceThresholdLocked()
		if confidence.ShouldAbstainAt(score, threshold) {
			obs.FromCtx(ctx).Info("router_abstain_low_confidence",
				"score", float64(score),
				"threshold", float64(threshold))
			// Nil + nil is the documented "fall back to full
			// catalog" path on routerFn. The narrower at the call
			// site treats a nil result as "router opted out".
			return nil, nil
		}
	}

	// Try the object form first; fall through to the legacy bare
	// array if the response shape is `["wifi","bt"]`.
	var arr []string
	if strings.HasPrefix(text, "{") {
		var obj struct {
			Groups []string `json:"groups"`
		}
		if err := json.Unmarshal([]byte(text), &obj); err != nil {
			return nil, fmt.Errorf("router returned non-JSON object: %q", text)
		}
		arr = obj.Groups
	} else if err := json.Unmarshal([]byte(text), &arr); err != nil {
		// A router that babbles prose instead of JSON is worse than no
		// router — fall back to full catalog.
		return nil, fmt.Errorf("router returned non-JSON: %q", text)
	}
	selected := make(map[string]bool, len(arr))
	for _, s := range arr {
		s = strings.TrimSpace(s)
		if s != "" {
			selected[s] = true
		}
	}
	return selected, nil
}

// routerConfidenceThresholdLocked returns the active persona's
// router-confidence threshold, or 0 (which ShouldAbstainAt
// normalises to the default) when no persona is set or no override
// is configured. Caller MUST hold a.mu.
func (a *Agent) routerConfidenceThresholdLocked() confidence.Score {
	p := a.persona
	if p == nil {
		return 0
	}
	v, ok := p.Confidence[string(confidence.KindRouter)]
	if !ok {
		return 0
	}
	return confidence.Score(v)
}

// EnableDynamicCatalog opts the agent into per-turn tool narrowing via
// the Haiku-class router. Off by default; operators enable it through
// config once they've measured the tradeoff (typically a ~500 ms
// latency bump in exchange for 60-80 % fewer tool-description tokens
// per turn).
func (a *Agent) EnableDynamicCatalog() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routerFn = a.routeGroups
}

// DisableDynamicCatalog reverts to the full catalog on every turn.
// Primarily useful for tests that share an agent and want to toggle
// the feature between cases.
func (a *Agent) DisableDynamicCatalog() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.routerFn = nil
}

// narrowToolsByAttack filters tools to those tagged with at least one
// of the provided MITRE ATT&CK technique IDs (per the internal/attack
// Index). Tools in alwaysOnGroups pass through unchanged so the
// operator never loses audit / meta primitives mid-constraint.
//
// Correctness floors mirror narrowTools:
//   - empty techniques OR nil index -> input unchanged
//   - filtered result below minNarrowedTools -> input unchanged
//
// The function is deliberately pure + deterministic so it can feed
// the Haiku router's prompt construction (P0-04) and the future
// Campaigns runner (P2-19) without sharing agent state.
func narrowToolsByAttack(tools []anthropic.ToolUnionParam, idx *attack.Index, techniques []string) []anthropic.ToolUnionParam {
	if len(techniques) == 0 || idx == nil {
		return tools
	}
	allowed := make(map[string]bool, len(techniques))
	for _, t := range techniques {
		t = strings.TrimSpace(t)
		if t != "" {
			allowed[t] = true
		}
	}
	if len(allowed) == 0 {
		return tools
	}

	out := make([]anthropic.ToolUnionParam, 0, len(tools))
	for _, t := range tools {
		if t.OfTool == nil {
			out = append(out, t)
			continue
		}
		g := ToolGroup(t.OfTool.Name)
		if alwaysOnGroups[g] {
			out = append(out, t)
			continue
		}
		for _, tag := range idx.TechniquesForTool(t.OfTool.Name) {
			if allowed[tag] {
				out = append(out, t)
				break
			}
		}
	}
	if len(out) < minNarrowedTools {
		return tools
	}
	return out
}

// SetAttackIndex wires an ATT&CK index onto the agent so the router
// and the runtime constraint filter (SetAttackConstraint) can resolve
// tool-to-technique mappings. Nil detaches the index.
func (a *Agent) SetAttackIndex(idx *attack.Index) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attackIdx = idx
}

// AttackIndex returns the installed ATT&CK index, or nil. Used by
// /report and the REPL /attack command.
func (a *Agent) AttackIndex() *attack.Index {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.attackIdx
}

// SetAttackConstraint limits the agent's per-turn tool catalog to
// tools tagged with at least one of the given ATT&CK technique IDs.
// Pass an empty slice to clear the constraint. Unknown IDs are kept
// verbatim — the filter simply won't match any tool for them, which
// is the conservative behaviour when a user pastes a technique that
// isn't in the curated registry yet.
func (a *Agent) SetAttackConstraint(techniques []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(techniques) == 0 {
		a.attackConstraint = nil
		return
	}
	cleaned := make([]string, 0, len(techniques))
	seen := map[string]bool{}
	for _, t := range techniques {
		t = strings.TrimSpace(t)
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		cleaned = append(cleaned, t)
	}
	a.attackConstraint = cleaned
}

// AttackConstraint returns a copy of the current technique-ID
// constraint set. Returns an empty slice when no constraint is
// installed.
func (a *Agent) AttackConstraint() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.attackConstraint) == 0 {
		return nil
	}
	out := make([]string, len(a.attackConstraint))
	copy(out, a.attackConstraint)
	return out
}
