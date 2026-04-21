package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Verdict is the structured output of a Detector. Grep-friendly on
// wire: downstream consumers (reports, audit analytics, the future
// Campaigns runner) pattern-match on Verdict alone rather than parsing
// free-form Evidence prose.
//
// The three-value scheme maps to Garak / PyRIT's probe detector
// taxonomy: a tool invocation has a clean success, a clean failure,
// or a deceptive / ambiguous response that merits follow-up
// ("suspicious"). The suspicious bucket is the important addition —
// a deauth tool that reports success despite the target ignoring it
// produces a suspicious verdict, not a success.
type Verdict struct {
	Verdict    string  `json:"verdict"`               // "success" | "failure" | "suspicious" | "unknown"
	Confidence float64 `json:"confidence"`            // 0.0-1.0
	Evidence   string  `json:"evidence,omitempty"`    // one or two sentences citing the output
	DetectedBy string  `json:"detected_by,omitempty"` // detector name, set by Engine
}

// Known verdict values. Callers should prefer these constants over
// string literals so a typo becomes a compile error.
const (
	VerdictSuccess    = "success"
	VerdictFailure    = "failure"
	VerdictSuspicious = "suspicious"
	VerdictUnknown    = "unknown"
)

// JSON serialises the verdict to a compact wire representation. Used
// for audit-log attachment and /report rendering.
func (v Verdict) JSON() string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"verdict":"unknown","confidence":0,"evidence":"marshal failed"}`
	}
	return string(b)
}

// Detector evaluates a tool invocation and emits a Verdict. The input
// is the tool's JSON arguments, the output is whatever the tool
// returned (possibly wrapped in ToolError JSON on failure). The name
// is the tool name for routing context-specific prompts.
//
// Implementations must honour ctx cancellation — detectors are often
// LLM-backed and can otherwise wedge the caller for tens of seconds
// on a slow classifier model.
type Detector interface {
	Name() string
	Evaluate(ctx context.Context, tool, input, output string) (Verdict, error)
}

// JudgeFunc is the LLM-as-judge callback used by LLMDetector. Takes a
// system prompt + a user message and returns the judge's raw text
// output. Injected here so unit tests can substitute a deterministic
// stub without wiring up the Anthropic SDK. In production wiring this
// is typically a thin wrapper over the agent's TierClassify model
// (Haiku).
type JudgeFunc func(ctx context.Context, system, user string) (string, error)

// LLMDetector turns a system prompt + a JudgeFunc into a Detector.
// The judge is asked to return JSON matching the Verdict shape; any
// parsing failure (prose instead of JSON, missing verdict field)
// surfaces as a VerdictUnknown so downstream code can decide whether
// to retry or escalate.
type LLMDetector struct {
	DetectorName string
	SystemPrompt string
	Judge        JudgeFunc
}

// Name returns the detector's registration name.
func (d *LLMDetector) Name() string { return d.DetectorName }

// Evaluate runs the judge and parses its response into a Verdict.
// Any error path produces a structured VerdictUnknown rather than a
// Go error — a broken detector must never derail the caller (detector
// outputs are advisory).
func (d *LLMDetector) Evaluate(ctx context.Context, tool, input, output string) (Verdict, error) {
	if d.Judge == nil {
		return Verdict{Verdict: VerdictUnknown, DetectedBy: d.DetectorName, Evidence: "no judge configured"}, nil
	}
	userMsg := fmt.Sprintf("tool: %s\ninput: %s\noutput: %s", tool, input, output)
	raw, err := d.Judge(ctx, d.SystemPrompt, userMsg)
	if err != nil {
		return Verdict{Verdict: VerdictUnknown, DetectedBy: d.DetectorName, Evidence: fmt.Sprintf("judge error: %v", err)}, nil
	}
	v := parseVerdict(raw)
	v.DetectedBy = d.DetectorName
	return v, nil
}

// parseVerdict extracts a Verdict from the judge's raw response. The
// judge is asked for JSON but models sometimes emit prose or markdown
// fences; parseVerdict tries hardest to extract structure and falls
// back to VerdictUnknown when nothing usable is found.
func parseVerdict(raw string) Verdict {
	trimmed := strings.TrimSpace(raw)
	// Strip markdown fences the judge occasionally emits despite the
	// system prompt asking for raw JSON.
	if strings.HasPrefix(trimmed, "```") {
		trimmed = strings.TrimPrefix(trimmed, "```json")
		trimmed = strings.TrimPrefix(trimmed, "```")
		trimmed = strings.TrimSuffix(trimmed, "```")
		trimmed = strings.TrimSpace(trimmed)
	}
	if trimmed == "" {
		return Verdict{Verdict: VerdictUnknown, Evidence: "empty judge response"}
	}
	var v Verdict
	if err := json.Unmarshal([]byte(trimmed), &v); err != nil {
		return Verdict{Verdict: VerdictUnknown, Evidence: "judge response was not JSON"}
	}
	if v.Verdict == "" {
		v.Verdict = VerdictUnknown
	}
	// Clamp confidence to a sane range so a spurious 1e9 in the
	// response doesn't propagate downstream.
	if v.Confidence < 0 {
		v.Confidence = 0
	}
	if v.Confidence > 1 {
		v.Confidence = 1
	}
	return v
}

// Built-in detector prompts. Each is a compact, Haiku-friendly
// instruction that defines success/failure/suspicious for one tool
// family. Factored out so operators can override them via config
// without a code change (future work — today they're hard-coded).
const (
	deauthJudgePrompt = `You are judging whether a WiFi deauthentication attack against a target station actually disconnected that station. ` +
		`Input: tool args + raw output. Success = station appears disconnected (STA count dropped, the tool reports frames sent AND ack / miss statistics indicate the target reacted). ` +
		`Failure = tool failed to run or reports no frames sent. ` +
		`Suspicious = tool claims success but output is generic / empty / identical to a dry-run. ` +
		`Return ONLY a JSON object matching {"verdict":"success|failure|suspicious","confidence":0.0-1.0,"evidence":"one sentence"} and nothing else.`

	pmkidJudgePrompt = `You are judging whether a PMKID capture produced a valid handshake usable offline. ` +
		`Input: tool args + raw output. ` +
		`Success = output contains a hex PMKID and a BSSID:SSID pair. ` +
		`Failure = tool errored or no PMKID line in output. ` +
		`Suspicious = output claims capture but no PMKID hex present / output matches a no-AP-in-range empty-capture template. ` +
		`Return ONLY a JSON object matching {"verdict":"success|failure|suspicious","confidence":0.0-1.0,"evidence":"one sentence"}.`

	nfcCloneJudgePrompt = `You are judging the fidelity of an NFC clone: did the emulation match the source tag's UID + block layout? ` +
		`Input: tool args + raw output (post-emulate reader probe). ` +
		`Success = reader reports a matching UID and at least the first 4 MIFARE blocks round-trip. ` +
		`Failure = reader reports no tag / wrong UID / ATQA mismatch. ` +
		`Suspicious = UID matches but read-back blocks are all zero / obviously from a blank tag. ` +
		`Return ONLY a JSON object matching {"verdict":"success|failure|suspicious","confidence":0.0-1.0,"evidence":"one sentence"}.`
)

// NewDeauthSuccessDetector returns the built-in deauth judge.
func NewDeauthSuccessDetector(judge JudgeFunc) *LLMDetector {
	return &LLMDetector{DetectorName: "wifi_deauth_success", SystemPrompt: deauthJudgePrompt, Judge: judge}
}

// NewPMKIDValidityDetector returns the built-in PMKID judge.
func NewPMKIDValidityDetector(judge JudgeFunc) *LLMDetector {
	return &LLMDetector{DetectorName: "pmkid_capture_validity", SystemPrompt: pmkidJudgePrompt, Judge: judge}
}

// NewNFCCloneFidelityDetector returns the built-in NFC-clone judge.
func NewNFCCloneFidelityDetector(judge JudgeFunc) *LLMDetector {
	return &LLMDetector{DetectorName: "nfc_clone_fidelity", SystemPrompt: nfcCloneJudgePrompt, Judge: judge}
}
