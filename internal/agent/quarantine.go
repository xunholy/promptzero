package agent

import (
	"regexp"
	"strings"
)

// ANSI CSI escape sequences (colour, cursor move, etc.) emitted by Flipper
// firmware. These are meaningless inside a tool_result block and are a
// common vector for terminal-injection games against humans tailing logs,
// so they are stripped before any output reaches the model or the audit
// log. Kept in sync with the equivalent regex in internal/flipper; the
// two are intentionally decoupled because they run at different layers
// (this one runs on *every* tool output, not just Flipper serial).
var ansiCSIRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// Non-printable control bytes stripped after ANSI: NUL through BEL/BS,
// vertical tab, form feed, SO through US, and DEL. Newline (\x0a),
// carriage return (\x0d), and tab (\x09) are preserved — Flipper and
// Marauder both emit tabular output using those characters.
var otherControlsRE = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]`)

// notWrappedTools names tools whose output originates inside PromptZero
// (structured JSON, our own summaries, vision-model narration) rather
// than from attacker-controllable hardware. Their output is *not*
// wrapped in <untrusted-hardware-output> tags — the content is trusted
// by construction.
//
// Every other tool — anything that returns raw Flipper or Marauder
// serial output, NFC/RFID reads, WiFi scan results, storage reads,
// system logs, etc. — is wrapped by default. This is an allowlist by
// design: forgetting to mark a new structured tool will only cost a
// few tokens of tag overhead, whereas forgetting to mark a new
// hardware tool would leak untrusted text straight into the model's
// instruction stream.
var notWrappedTools = map[string]struct{}{
	// Pure internal / configuration surfaces.
	"list_devices": {},

	// Vision analysis — output is the analysing model's own narration,
	// not the raw image.
	"analyze_image": {},

	// Audit log — content comes from our own SQLite store.
	"audit_query":  {},
	"audit_export": {},
	"audit_stats":  {},

	// SD-card discovery summary — produced by our scanner, not by the
	// Flipper CLI verbatim.
	"discover_apps": {},

	// Structured file-format JSON — our parser owns the serialisation
	// shape even though the underlying file can be attacker-controlled.
	// (The LLM relies on the JSON shape; wrapping would disrupt it. The
	// parser rejects malformed input.)
	"fileformat_read": {},
	"fileformat_edit": {},
	"fileformat_diff": {},

	// Generation pipeline — output is our own preview/path text.
	"generate_evil_portal": {},
	"generate_badusb":      {},
	"generate_subghz":      {},
	"generate_ir":          {},
	"generate_nfc":         {},
	"run_payload":          {},
	"generate_deploy_run":  {},

	// Composite workflows — they orchestrate hardware calls internally
	// but emit structured summaries at the top level.
	"workflow_nfc_badge_pipeline":       {},
	"workflow_wifi_target_to_hashcat":   {},
	"workflow_garage_door_triage":       {},
	"workflow_rolljam_lab_demo":         {},
	"workflow_phys_pentest_badge_walk":  {},
	"workflow_hw_recon_blackbox_device": {},
	"workflow_badusb_target_profile":    {},
}

// isUntrustedHardwareOutput reports whether a tool's successful output
// should be wrapped in <untrusted-hardware-output> delimiters before it
// reaches the model. True for every tool not in the notWrappedTools
// allowlist.
func isUntrustedHardwareOutput(toolName string) bool {
	_, ok := notWrappedTools[toolName]
	return !ok
}

// sanitizeControlChars strips ANSI CSI escape sequences and non-printable
// ASCII control bytes (preserving newline, carriage return, and tab). The
// return value is safe to embed inside a tool_result block or audit row
// without risk of terminal-control games or visual spoofing.
func sanitizeControlChars(s string) string {
	s = ansiCSIRE.ReplaceAllString(s, "")
	s = otherControlsRE.ReplaceAllString(s, "")
	return s
}

// quarantineOutput runs sanitizeControlChars on every output and, for
// hardware-origin tools that completed without error, wraps the result
// in <untrusted-hardware-output> delimiters. Error strings (isErr=true)
// are sanitised but not wrapped — error messages are formatted by our
// own dispatch code, not captured from hardware.
//
// The wrapping is the countermeasure for prompt-injection attacks where
// attacker-controllable content (SSIDs, NFC tag URIs, BLE device names,
// NDEF records, filenames on the SD card) is fed back to the model as
// tool output. The paired clause in the system prompt tells the model
// to treat content inside these tags as data, not instructions.
func quarantineOutput(toolName, output string, isErr bool) string {
	sanitized := sanitizeControlChars(output)
	if isErr || !isUntrustedHardwareOutput(toolName) {
		return sanitized
	}
	// Trim trailing whitespace so the closing tag lands on its own line.
	sanitized = strings.TrimRight(sanitized, " \t\r\n")
	return "<untrusted-hardware-output>\n" + sanitized + "\n</untrusted-hardware-output>"
}
