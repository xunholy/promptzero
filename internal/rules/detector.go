package rules

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
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
		// Fallback: judges sometimes emit valid JSON wrapped in prose
		// ("Based on the output: {...}\nReasoning: ..."). Extract the
		// first balanced {...} block and retry. Cheap brace-balance
		// scan; quote-aware so braces inside strings don't confuse it.
		if block, ok := extractJSONObject(trimmed); ok {
			if err := json.Unmarshal([]byte(block), &v); err != nil {
				return Verdict{Verdict: VerdictUnknown, Evidence: "judge response was not JSON"}
			}
		} else {
			return Verdict{Verdict: VerdictUnknown, Evidence: "judge response was not JSON"}
		}
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

// extractJSONObject walks s left-to-right, finds the first '{' that
// starts a balanced object, and returns that substring. Quote-aware:
// braces inside JSON string literals don't affect the depth counter,
// and a backslash escapes the next character inside a string. Returns
// (substring, true) on success, ("", false) when no balanced object
// begins after the first '{'. Used as a tolerant-mode fallback for
// LLM judge responses that wrap their JSON in prose.
func extractJSONObject(s string) (string, bool) {
	start := strings.IndexByte(s, '{')
	if start < 0 {
		return "", false
	}
	depth := 0
	inStr := false
	escaped := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if inStr {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1], true
			}
		}
	}
	return "", false
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

// DetectorEngine is a per-tool detector registry with a concurrent
// evaluator. The agent calls EvaluateFor after a tool invocation and
// receives every registered detector's Verdict. Multiple detectors
// can register for the same tool — useful when a single tool has
// orthogonal success criteria (e.g. wifi_deauth both "disconnected
// the station" and "didn't trip the vendor's rate-limit").
//
// Safe for concurrent registration + evaluation; zero value is NOT
// usable — call NewDetectorEngine.
type DetectorEngine struct {
	mu          sync.RWMutex
	byTool      map[string][]Detector
	evalTimeout time.Duration
}

// NewDetectorEngine returns an Engine with the given per-detector
// timeout. Timeout caps how long a single detector call can block
// EvaluateFor — detectors are LLM-backed and a stalled classifier
// API would otherwise wedge the agent turn. Ten seconds matches the
// verifier's default (see internal/agent/verify.go).
func NewDetectorEngine(timeout time.Duration) *DetectorEngine {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &DetectorEngine{
		byTool:      make(map[string][]Detector),
		evalTimeout: timeout,
	}
}

// Register installs a detector to run after any invocation of the
// named tool. A single detector can be registered against multiple
// tools (e.g. the deauth-success judge matches both wifi_deauth and
// wifi_deauth_station_list).
func (e *DetectorEngine) Register(toolName string, d Detector) {
	if e == nil || d == nil || toolName == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.byTool[toolName] = append(e.byTool[toolName], d)
}

// RegisterForMany is a convenience wrapper that registers d against
// every name in tools. Useful for built-in detectors that should
// fire on a family of related tools.
func (e *DetectorEngine) RegisterForMany(tools []string, d Detector) {
	for _, t := range tools {
		e.Register(t, d)
	}
}

// HasDetectorsFor reports whether the engine has at least one
// detector registered for toolName. Callers use this to skip the
// EvaluateFor round-trip entirely when no detector is listening.
func (e *DetectorEngine) HasDetectorsFor(toolName string) bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.byTool[toolName]) > 0
}

// EvaluateFor runs every detector registered for toolName and
// returns their Verdicts. Detectors run concurrently under the
// engine's timeout — any detector that errors or times out
// contributes a VerdictUnknown rather than taking down the whole
// evaluation. Returns an empty slice when no detectors are
// registered for the tool.
func (e *DetectorEngine) EvaluateFor(ctx context.Context, toolName, input, output string) []Verdict {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	detectors := append([]Detector(nil), e.byTool[toolName]...)
	e.mu.RUnlock()
	if len(detectors) == 0 {
		return nil
	}

	verdicts := make([]Verdict, len(detectors))
	var wg sync.WaitGroup
	for i, d := range detectors {
		wg.Add(1)
		go func(i int, d Detector) {
			defer wg.Done()

			// Apply per-detector timeout to prevent a single stalled
			// classifier from blocking the entire evaluation round.
			detCtx, cancel := context.WithTimeout(ctx, e.evalTimeout)
			defer cancel()

			v, err := d.Evaluate(detCtx, toolName, input, output)
			if err != nil {
				v = Verdict{
					Verdict:    VerdictUnknown,
					DetectedBy: d.Name(),
					Evidence:   fmt.Sprintf("detector error: %v", err),
				}
			}
			verdicts[i] = v
		}(i, d)
	}
	wg.Wait()
	return verdicts
}

// RegisterBuiltins installs the three built-in detectors against
// the standard tool surfaces they judge. All share a single
// JudgeFunc — typically a thin wrapper over the agent's
// classification-tier Anthropic client. Returns the engine so
// callers can chain.
func (e *DetectorEngine) RegisterBuiltins(judge JudgeFunc) *DetectorEngine {
	e.RegisterForMany([]string{"wifi_deauth", "wifi_deauth_station_list"}, NewDeauthSuccessDetector(judge))
	e.Register("wifi_sniff_pmkid", NewPMKIDValidityDetector(judge))
	e.Register("nfc_emulate", NewNFCCloneFidelityDetector(judge))
	return e
}
