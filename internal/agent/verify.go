package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
)

// verifyTimeout caps how long the chain-of-verification pass can
// block the agent turn. Ten seconds is enough for a Haiku call on a
// normal link; a hung classifier API wedging the whole turn (Run
// holds a.mu throughout) is a worse failure mode than an uncertified
// verdict, so on timeout we degrade to "uncertified" and proceed.
const verifyTimeout = 10 * time.Second

// Chain-of-verification for generated payloads (P1-16). After a
// generate_* tool produces content, a classification-tier model pass
// analyses it against known failure modes for that payload type and
// returns a structured verdict. High/critical verdicts block the
// deploy step unless the caller passes verify_bypass=true.
//
// The point isn't to replace the existing validator package (which
// does static BadUSB sandbox analysis) — it's to catch the LLM-level
// mistakes a static analyser can't, e.g. "this evil portal posts to
// /login instead of /get", "this BadUSB script assumes NumLock is
// off", "this .sub uses a frequency the TX radio can't reach".
//
// Verdict severities are grep-friendly strings matching the existing
// detector (P1-10) and validator (internal/validator) vocabularies:
//   "none"     — no failure modes detected
//   "low"      — cosmetic / non-functional issues
//   "medium"   — may reduce effectiveness, deploy anyway
//   "high"     — likely to fail / misbehave; deploy is blocked
//   "critical" — will fire on the wrong target or cause side-effects

// Known severity values.
const (
	VerifySeverityNone     = "none"
	VerifySeverityLow      = "low"
	VerifySeverityMedium   = "medium"
	VerifySeverityHigh     = "high"
	VerifySeverityCritical = "critical"
)

// VerificationVerdict is the structured output of a verify pass.
type VerificationVerdict struct {
	Severity       string   `json:"severity"`
	FailureModes   []string `json:"failure_modes,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	Verified       bool     `json:"verified"`
}

// verifyFunc is the pluggable per-verification callback. The default
// production wiring calls an Anthropic classification-tier model
// (Haiku) with a payload-type-specific system prompt; tests install
// a synchronous stub to exercise the block / bypass logic without a
// live client.
type verifyFunc func(ctx context.Context, payloadType, content string) (VerificationVerdict, error)

// shouldBlockDeploy reports whether a verdict should stop the deploy
// step from running. Bypass=true forces a deploy regardless of
// severity — kept separate from the verdict itself so an audit row
// can show both "verifier said HIGH" and "operator bypassed".
func shouldBlockDeploy(v VerificationVerdict, bypass bool) bool {
	if bypass {
		return false
	}
	switch v.Severity {
	case VerifySeverityHigh, VerifySeverityCritical:
		return true
	default:
		return false
	}
}

// verifyPayloadSystemPrompts map each generate_* type to a focused
// system prompt. Kept short so the Haiku verifier stays fast.
// Operators who want to customise would override via future config.
var verifyPayloadSystemPrompts = map[string]string{
	"evil_portal": "You are reviewing a Flipper Zero Evil Portal HTML payload. Check for: " +
		"(a) missing or wrong form action (must be '/get'), (b) wrong form method (must be 'GET'), " +
		"(c) credential fields not named exactly 'email' and 'password', (d) external resource " +
		"references (img src pointing off-site, CDN links, external CSS — all break when served " +
		"offline from the Marauder), (e) obvious markdown fence leakage. " +
		"Output ONLY a JSON object matching {\"severity\":\"none|low|medium|high|critical\"," +
		"\"failure_modes\":[\"...\"],\"recommendation\":\"...\",\"verified\":true}. " +
		"Deploy-blocking issues (a/b/c/d) are 'high'; cosmetic issues are 'low'.",

	"badusb": "You are reviewing a Flipper Zero BadUSB DuckyScript payload. Check for: " +
		"(a) target-OS mismatch (e.g. Windows shortcuts on a macOS target), (b) unbounded loops " +
		"without a BREAK condition, (c) destructive rm/format/shred invocations that weren't in " +
		"the description, (d) reliance on NumLock being off when script uses numpad, (e) missing " +
		"DELAY after GUI key combos so WIN+R opens before typing. " +
		"Output ONLY a JSON object matching {\"severity\":\"none|low|medium|high|critical\"," +
		"\"failure_modes\":[\"...\"],\"recommendation\":\"...\",\"verified\":true}. " +
		"Destructive unintended ops are 'critical'; reliability bugs are 'high'.",

	"subghz": "You are reviewing a Flipper Zero .sub SubGHz signal file. Check for: " +
		"(a) frequency outside the CC1101 1 MHz-1 GHz range, (b) Preset that doesn't match the band " +
		"(FSK preset on an OOK-only freq, etc.), (c) Protocol and Key bit-length mismatch, " +
		"(d) missing required headers (Filetype, Frequency, Preset). " +
		"Output ONLY a JSON object matching {\"severity\":\"none|low|medium|high|critical\"," +
		"\"failure_modes\":[\"...\"],\"recommendation\":\"...\",\"verified\":true}. " +
		"Out-of-band freq is 'critical'; missing headers are 'high'.",

	"ir": "You are reviewing a Flipper Zero .ir universal-remote file. Check for: " +
		"(a) missing required signal fields (each signal needs a 'name' and either " +
		"protocol/address/command OR frequency/duty_cycle/data), (b) raw signals with " +
		"fewer than 4 data samples, (c) address/command hex of the wrong length for the protocol. " +
		"Output ONLY a JSON object matching {\"severity\":\"none|low|medium|high|critical\"," +
		"\"failure_modes\":[\"...\"],\"recommendation\":\"...\",\"verified\":true}. " +
		"Missing required fields are 'high'.",

	"nfc": "You are reviewing a Flipper Zero .nfc tag file. Check for: " +
		"(a) missing Filetype or UID headers; " +
		"(b) UID length mismatch for the declared DeviceType (Mifare Classic 1K = 4 or 7 byte UID, NTAG = 7 byte); " +
		"(c) Block contents that are all zeros when Mifare Classic would normally carry Access Bits + a non-zero key block; " +
		"(d) SAK byte vs declared MifareType mismatch (Classic 1K SAK=08, Classic 4K SAK=18, Ultralight SAK=00, NTAG SAK=00); " +
		"(e) Mifare Classic sector trailers (blocks 3, 7, 11, 15, ...) with incorrect Access Bits — bytes 6-8 must encode C1/C2/C3 with their inverse pairs, standard value is 'FF 07 80' for free read/write access; " +
		"(f) Mifare Classic sector trailers missing or zero-filled KeyA (bytes 0-5) or KeyB (bytes 10-15); " +
		"(g) block index overflow for declared type (Classic 1K = 64 blocks, Classic 4K = 256 blocks, NTAG213 = 45 pages, NTAG215 = 135, NTAG216 = 231); " +
		"(h) NDEF-only payload marked as Classic (no Access Bits in any sector trailer). " +
		"Output ONLY a JSON object matching {\"severity\":\"none|low|medium|high|critical\"," +
		"\"failure_modes\":[\"...\"],\"recommendation\":\"...\",\"verified\":true}. " +
		"Missing headers, UID/SAK mismatch, Access Bits errors, and block overflow are 'high'; NDEF-on-Classic and placeholder keys are 'medium'.",

	"rfid": "You are reviewing a Flipper Zero .rfid LF badge file. Check for: " +
		"(a) missing Filetype or Key type / Data headers, (b) Data hex length wrong for the Key type " +
		"(EM4100 = 10 hex chars, HIDProx = 12 hex chars, Indala = varies), (c) Data being a well-known " +
		"placeholder (all zeros, all F, 0123456789). " +
		"Output ONLY a JSON object matching {\"severity\":\"none|low|medium|high|critical\"," +
		"\"failure_modes\":[\"...\"],\"recommendation\":\"...\",\"verified\":true}. " +
		"Length mismatch is 'high'; placeholder data is 'medium'.",
}

// verifyPayload runs the production verifier: a single Haiku-tier
// call with a payload-type-specific system prompt. Returns a verdict
// parsed from the model's JSON output, or a benign {Severity:"none",
// Verified:false} on any error — a broken verifier must never
// propagate up through generate_* and block the caller.
//
// Concurrency contract: caller MUST hold a.mu (reads a.persona via
// modelForLocked and a.client without re-locking).
func (a *Agent) verifyPayload(ctx context.Context, payloadType, content string) (VerificationVerdict, error) {
	system, ok := verifyPayloadSystemPrompts[payloadType]
	if !ok {
		// Unknown payload types skip verification — don't error out.
		return VerificationVerdict{Severity: VerifySeverityNone, Verified: false}, nil
	}

	// Truncate long content before sending to the verifier — the
	// first 4000 bytes are almost always enough to catch structural
	// issues, and sending 60KB of HTML to Haiku on every generate
	// would defeat the cost argument.
	trimmed := content
	if len(trimmed) > 4000 {
		trimmed = trimmed[:4000] + "\n…(truncated)"
	}

	model := a.modelForLocked(TierClassify)
	// Enforce a hard timeout so a stalled classifier API can't wedge
	// the whole agent turn — Run holds a.mu for the duration of
	// verifyPayload, so "just wait" is not acceptable.
	callCtx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	resp, err := a.client.Messages.New(callCtx, anthropic.MessageNewParams{
		Model:     anthropic.Model(model),
		MaxTokens: 256,
		System:    []anthropic.TextBlockParam{{Text: system}},
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(trimmed))},
	})
	if err != nil {
		return VerificationVerdict{Severity: VerifySeverityNone, Verified: false}, nil
	}

	var raw string
	for _, b := range resp.Content {
		if b.Type == "text" {
			raw += b.Text
		}
	}
	return parseVerificationVerdict(raw), nil
}

// parseVerificationVerdict extracts a verdict from the verifier's raw
// text response. Robust against: leading prose preambles, markdown
// fences (both ```json and bare ```), trailing commentary, and
// case-variant fence tags (```JSON). Strategy: find the first '{' and
// the last '}' and treat that byte range as candidate JSON. If that
// doesn't unmarshal, return uncertified.
//
// Returning {Severity:"none", Verified:false} on parse failure means
// the caller treats the generation as uncertified rather than failing
// hard — a flaky verifier must never block a generation.
func parseVerificationVerdict(raw string) VerificationVerdict {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return VerificationVerdict{Severity: VerifySeverityNone, Verified: false}
	}
	candidate := extractJSONObject(trimmed)
	if candidate == "" {
		return VerificationVerdict{Severity: VerifySeverityNone, Verified: false}
	}
	var v VerificationVerdict
	if err := json.Unmarshal([]byte(candidate), &v); err != nil {
		return VerificationVerdict{Severity: VerifySeverityNone, Verified: false}
	}
	if v.Severity == "" {
		v.Severity = VerifySeverityNone
	}
	return v
}

// extractJSONObject returns the substring of s that looks like a
// top-level JSON object — from the first '{' to the matching '}'
// (tracked by brace depth, respecting string literals). Returns "" if
// the input doesn't contain a balanced object. Intentionally more
// forgiving than "first { to last }" so strings with braces don't
// mis-match.
func extractJSONObject(s string) string {
	start := strings.Index(s, "{")
	if start < 0 {
		return ""
	}
	depth := 0
	inString := false
	escape := false
	for i := start; i < len(s); i++ {
		c := s[i]
		if escape {
			escape = false
			continue
		}
		if c == '\\' && inString {
			escape = true
			continue
		}
		if c == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return ""
}

// verdictSummary renders the verdict as a compact, human-readable
// string for inclusion in the tool result's text payload. The raw
// JSON goes through as well via the ToolResult JSON handling, but a
// prose summary helps the operator eyeball what the verifier saw.
func verdictSummary(v VerificationVerdict) string {
	if !v.Verified && v.Severity == VerifySeverityNone {
		return "(verifier: uncertified — check model / payload type)"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "verifier: %s", v.Severity)
	if len(v.FailureModes) > 0 {
		fmt.Fprintf(&b, "; issues: %s", strings.Join(v.FailureModes, "; "))
	}
	if v.Recommendation != "" {
		fmt.Fprintf(&b, "; recommendation: %s", v.Recommendation)
	}
	return b.String()
}
