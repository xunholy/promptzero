package agent

import (
	"encoding/json"
	"strings"
)

// ToolError is the canonical shape of a failed tool result, serialised
// as JSON into the tool_result content block. Replaces the old
// free-form "error: <message>" string so reflexion (P0-05), detectors
// (P1-10), and report generation (P1-11) can pattern-match on structure
// rather than scraping text.
//
// Fields stay flat so the LLM can reason over the shape without nested
// destructuring. Device state is deliberately excluded — it already
// ships on every user turn via the state-oracle block (P0-03) and would
// duplicate otherwise.
type ToolError struct {
	// Code is a machine-matchable failure class. Uses snake_case.
	// Examples: "flipper_timeout", "marauder_disconnect",
	// "storage_not_ready", "unknown_error".
	Code string `json:"code"`

	// Tool is the tool name that errored. Included so a detector or
	// audit consumer doesn't have to re-correlate with the surrounding
	// tool_use block.
	Tool string `json:"tool"`

	// Message is the original human-readable error text. Sanitised of
	// ANSI/control bytes — mirrors the quarantine pass applied to
	// successful output.
	Message string `json:"message"`

	// Excerpt is the last ~500 sanitised bytes of device I/O when
	// available. Gives the LLM textual context without shipping the
	// whole serial transcript.
	Excerpt string `json:"excerpt,omitempty"`

	// Remediation is a short (1-3 item) list of suggested next steps
	// derived from the error pattern. Examples: "reposition card",
	// "increase timeout_seconds", "reconnect BLE". Empty when no
	// heuristic matches.
	Remediation []string `json:"remediation,omitempty"`

	// Retryable signals whether blind retry has any chance of
	// succeeding. false for configuration / capability errors
	// ("not ready", "unknown protocol") so the main model doesn't
	// burn tool-call budget on hopeless retries.
	Retryable bool `json:"retryable"`
}

// JSON renders the error into the string form the agent splices into
// the tool_result content block. The encoder can only fail on invalid
// UTF-8 in Message / Excerpt, both of which pass through
// sanitizeControlChars first — so we swallow the error and fall back
// to a minimal struct representation.
func (e ToolError) JSON() string {
	b, err := json.Marshal(e)
	if err != nil {
		return `{"code":"marshal_error","tool":"` + e.Tool + `","message":"tool error failed to serialise","retryable":false}`
	}
	return string(b)
}

// toolErrExcerptMax caps the Excerpt field length so a pathological
// megabyte of device output can't inflate a single tool_result into a
// context-blowing payload. 500 bytes is enough for Flipper/Marauder
// tail output to carry meaningful diagnostic fragments.
const toolErrExcerptMax = 500

// newToolError classifies a failed dispatch result into a ToolError.
// Called at the agent boundary where (result, err) is available, so
// the ~100 per-tool wrappers in dispatch() don't each need to learn
// the new type.
//
// The code / remediation / retryable heuristics are intentionally
// conservative: unknown errors default to code=<group>_error,
// retryable=true, empty remediation — future detectors can be written
// against the Code field without breaking on novel messages.
func newToolError(toolName string, err error, excerpt string) ToolError {
	msg := ""
	if err != nil {
		msg = err.Error()
	}
	msg = sanitizeControlChars(msg)

	te := ToolError{
		Tool:      toolName,
		Message:   msg,
		Excerpt:   truncateExcerpt(sanitizeControlChars(excerpt)),
		Retryable: true,
	}

	// Pattern heuristics — ordered from most-specific to generic so
	// "marauder not connected" lands on "marauder_disconnect" rather
	// than the generic "disconnect" bucket.
	lower := strings.ToLower(msg)
	switch {
	case strings.Contains(lower, "marauder not connected"),
		strings.Contains(lower, "wifi devboard"):
		te.Code = "marauder_not_connected"
		te.Retryable = false
		te.Remediation = []string{"attach Marauder devboard", "restart promptzero with --wifi"}

	case strings.Contains(lower, "storage error: not ready"),
		strings.Contains(lower, "sd card"):
		te.Code = "storage_not_ready"
		te.Retryable = false
		te.Remediation = []string{"insert an SD card into the Flipper", "reseat the SD card"}

	case strings.Contains(lower, "timeout"),
		strings.Contains(lower, "deadline exceeded"):
		te.Code = errCodeForTool(toolName, "timeout")
		te.Retryable = true
		te.Remediation = []string{"increase timeout_seconds", "reposition the device/card/antenna", "retry"}

	case strings.Contains(lower, "disconnect"),
		strings.Contains(lower, "broken pipe"),
		strings.Contains(lower, "eof"),
		strings.Contains(lower, "no such device"):
		te.Code = errCodeForTool(toolName, "disconnect")
		te.Retryable = true
		te.Remediation = []string{"reconnect the Flipper cable", "run /reconnect", "for BLE: confirm pairing with bluetoothctl"}

	case strings.Contains(lower, "unknown tool"):
		te.Code = "unknown_tool"
		te.Retryable = false
		te.Remediation = []string{"consult /tools for the current catalog"}

	case strings.Contains(lower, "unknown protocol"),
		strings.Contains(lower, "unsupported"):
		te.Code = errCodeForTool(toolName, "unsupported")
		te.Retryable = false

	default:
		te.Code = errCodeForTool(toolName, "error")
	}
	return te
}

// errCodeForTool returns a "<group>_<suffix>" machine code keyed off
// the tool's logical group (see router.go). For instance,
// errCodeForTool("wifi_scan_ap", "timeout") -> "marauder_wifi_timeout".
func errCodeForTool(toolName, suffix string) string {
	group := ToolGroup(toolName)
	// Flatten "flipper.rf.subghz" -> "flipper_rf_subghz".
	flat := strings.ReplaceAll(group, ".", "_")
	return flat + "_" + suffix
}

// truncateExcerpt cuts s to at most toolErrExcerptMax bytes, preferring
// to keep the tail (where hardware error messages typically live). The
// "…" ellipsis is a 3-byte rune — accounted for in the tail budget so
// the returned string never exceeds the cap. A UTF-8-aware forward
// scan pushes the tail boundary to the next rune start so we never
// split a multi-byte character (firmware banners occasionally include
// non-ASCII).
func truncateExcerpt(s string) string {
	if len(s) <= toolErrExcerptMax {
		return s
	}
	const ellipsis = "…"
	tailStart := len(s) - (toolErrExcerptMax - len(ellipsis))
	// Advance to the next valid UTF-8 rune boundary so we never slice
	// through a multi-byte sequence. Continuation bytes match 10xxxxxx.
	for tailStart < len(s) && s[tailStart]&0xC0 == 0x80 {
		tailStart++
	}
	return ellipsis + s[tailStart:]
}
