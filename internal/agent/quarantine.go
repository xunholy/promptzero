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

// ansiC1RE catches C1 control strings that aren't CSI: OSC (ESC ]),
// DCS (ESC P), SOS (ESC X), PM (ESC ^), and APC (ESC _). These can
// (a) set a terminal window title from attacker-controlled text
// (OSC 0;<title>BEL), (b) carry hyperlinks (OSC 8;...;url ST text
// OSC 8;;ST) — where the url could be malicious — or (c) just emit
// arbitrary bytes a human reading raw output won't realise belong to
// a control string. The regex strips the full sequence including the
// payload, so the body never leaks to the model / audit / human log
// reader. Without it, the original implementation only stripped the
// leading ESC byte via otherControlsRE — leaving the payload as
// readable text. Terminator can be BEL (\x07) or ST (ESC \\).
var ansiC1RE = regexp.MustCompile(`\x1b[\]PX^_][^\x07\x1b]*(?:\x07|\x1b\\)`)

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
	"workflow_mousejack":                {},
}

// auditWrappedTools names tools that read from the audit log. Their
// output is structurally trusted (it comes from our own SQLite store)
// but the rows themselves can contain hardware-origin content from
// prior turns — captured SSIDs, NFC tag URIs, evil-portal harvested
// credentials, voice transcripts. Without wrapping, an adversarial
// NDEF payload from a previous session could launder itself into a
// later turn's instruction stream via an unwrapped audit_query result.
//
// Members get wrapped in <untrusted-audit-content> instead of
// <untrusted-hardware-output> so the model can treat them slightly
// differently: structured data with possibly-untrusted bytes inside,
// rather than raw live hardware bytes.
var auditWrappedTools = map[string]struct{}{
	"audit_query":  {},
	"audit_export": {},
	"audit_stats":  {},
}

// quarantineKind classifies a tool's quarantine policy. Three kinds:
// none (notWrappedTools allowlist), audit (auditWrappedTools), and
// hardware (the default — anything that returns hardware-origin data).
type quarantineKind int

const (
	quarantineNone     quarantineKind = iota // pass through, no wrapping
	quarantineAudit                          // wrap in <untrusted-audit-content>
	quarantineHardware                       // wrap in <untrusted-hardware-output>
)

func quarantineKindFor(toolName string) quarantineKind {
	if _, ok := notWrappedTools[toolName]; ok {
		return quarantineNone
	}
	if _, ok := auditWrappedTools[toolName]; ok {
		return quarantineAudit
	}
	return quarantineHardware
}

// isUntrustedHardwareOutput is kept for back-compat with quarantine_test.go;
// reports whether a tool gets the hardware wrapper specifically (audit
// quarantine doesn't qualify).
func isUntrustedHardwareOutput(toolName string) bool {
	return quarantineKindFor(toolName) == quarantineHardware
}

// sanitizeControlChars strips ANSI CSI escape sequences and non-printable
// ASCII control bytes (preserving newline, carriage return, and tab). The
// return value is safe to embed inside a tool_result block or audit row
// without risk of terminal-control games or visual spoofing.
func sanitizeControlChars(s string) string {
	s = ansiCSIRE.ReplaceAllString(s, "")
	// Run ansiC1RE before otherControlsRE so the leading ESC byte
	// is still present when the C1 regex matches. Without this
	// order the byte-stripper would consume \x1b first and the C1
	// body would survive as plain text.
	s = ansiC1RE.ReplaceAllString(s, "")
	s = otherControlsRE.ReplaceAllString(s, "")
	return s
}

// quarantineOutput runs sanitizeControlChars on every output and, for
// hardware-origin tools, wraps the result in <untrusted-hardware-output>
// delimiters regardless of whether the call succeeded or errored.
// Structured-internal tools (those in the notWrappedTools allowlist) are
// never wrapped.
//
// Error strings from hardware-origin tools are wrapped on the same rule
// as successes: error messages can contain attacker-controlled text
// (e.g., an SSID embedded in a connection-failure message) so they must
// be quarantined too.
//
// The wrapping is the countermeasure for prompt-injection attacks where
// attacker-controllable content (SSIDs, NFC tag URIs, BLE device names,
// NDEF records, filenames on the SD card) is fed back to the model as
// tool output. The paired clause in the system prompt tells the model
// to treat content inside these tags as data, not instructions.
func quarantineOutput(toolName, output string, isErr bool) string {
	_ = isErr // hardware errors carry the same risk as successes; wrap both
	sanitized := sanitizeControlChars(output)
	switch quarantineKindFor(toolName) {
	case quarantineNone:
		return sanitized
	case quarantineAudit:
		// Trim trailing whitespace so the closing tag lands on its own line.
		sanitized = strings.TrimRight(sanitized, " \t\r\n")
		return "<untrusted-audit-content>\n" + sanitized + "\n</untrusted-audit-content>"
	case quarantineHardware:
		fallthrough
	default:
		sanitized = strings.TrimRight(sanitized, " \t\r\n")
		return "<untrusted-hardware-output>\n" + sanitized + "\n</untrusted-hardware-output>"
	}
}
