// SPDX-License-Identifier: AGPL-3.0-or-later

// Package quarantine is the shared prompt-injection countermeasure for
// tool output. Any surface that feeds tool results back to an LLM — the
// agent's own dispatch loop and the MCP server that exposes the same tools
// to external MCP hosts — must run output through Output first, so
// attacker-controllable hardware bytes (SSIDs, NFC/NDEF URIs, BLE device
// names, SD-card filenames, sub-GHz payloads) can't smuggle instructions
// into the consuming model's context.
//
// The package is deliberately dependency-free (stdlib only) and keyed
// solely by tool name, so every surface shares one source of truth for
// which tools are attacker-controllable and how their output is wrapped.
package quarantine

import (
	"regexp"
	"strings"
)

// ANSI CSI escape sequences (colour, cursor move, etc.) emitted by Flipper
// firmware. These are meaningless inside a tool_result block and are a
// common vector for terminal-injection games against humans tailing logs,
// so they are stripped before any output reaches the model or the audit log.
var ansiCSIRE = regexp.MustCompile(`\x1b\[[0-9;?]*[A-Za-z]`)

// ansiC1RE catches C1 control strings that aren't CSI: OSC (ESC ]), DCS
// (ESC P), SOS (ESC X), PM (ESC ^), and APC (ESC _). These can set a
// terminal window title from attacker-controlled text, carry hyperlinks
// with a malicious URL, or emit arbitrary bytes a human reading raw output
// won't realise belong to a control string. The regex strips the full
// sequence including the payload. Terminator can be BEL (\x07) or ST (ESC \).
var ansiC1RE = regexp.MustCompile(`\x1b[\]PX^_][^\x07\x1b]*(?:\x07|\x1b\\)`)

// ansiC1UntermRE strips an UNTERMINATED C1 control string — an OSC/DCS/SOS/PM/
// APC whose BEL/ST terminator the attacker omitted so ansiC1RE (which requires
// the terminator) doesn't match. Without this the leading ESC alone is removed
// by otherControlsRE and the payload survives as readable text (e.g.
// "]0;PWNED do evil"), defeating the "strips the full sequence including the
// payload" guarantee. The match is bounded to the rest of the current line
// (it stops at \n, BEL, or another ESC) so a single unterminated sequence
// can't blank multi-line tool output below it. Applied after ansiC1RE so
// terminated sequences (and their terminators) are removed first.
var ansiC1UntermRE = regexp.MustCompile("\x1b[\\]PX^_][^\x07\x1b\n]*")

// otherControlsRE strips remaining non-printable control bytes after ANSI:
// NUL through BEL/BS, vertical tab, form feed, SO through US, DEL, and the
// 8-bit C1 controls U+0080–U+009F. The C1 range includes 8-bit forms of CSI
// (0x9B), OSC (0x9D), DCS (0x90), and NEL (0x85) — live terminal-control
// introducers on a Latin-1/8-bit terminal — so leaving them in would
// undermine the same "safe to embed raw" guarantee the ANSI strip provides.
// Newline (\x0a), carriage return (\x0d), and tab (\x09) are preserved —
// Flipper and Marauder both emit tabular output using those characters.
var otherControlsRE = regexp.MustCompile(`[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]`)

// notWrappedTools names tools whose output originates inside PromptZero
// (structured JSON, our own summaries, generated-payload previews) rather
// than from attacker-controllable hardware. Their output is not wrapped in
// <untrusted-hardware-output> tags — the content is trusted by construction.
//
// Every other tool — anything that returns raw Flipper or Marauder serial
// output, NFC/RFID reads, WiFi scan results, storage reads, system logs,
// etc. — is wrapped by default. This is an allowlist by design: forgetting
// to mark a new structured tool only costs a few tokens of tag overhead,
// whereas forgetting to mark a new hardware tool would leak untrusted text
// straight into the model's instruction stream.
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

	// Composite workflow whose output is entirely our own — a generated
	// payload preview plus deploy/run status. No phase reads
	// attacker-controlled data back, so the structured result is trusted.
	"workflow_badusb_target_profile": {},

	// NOTE: the hardware-READING workflows (wifi_target_to_hashcat,
	// nfc_badge_pipeline, phys_pentest_badge_walk, hw_recon_blackbox_device,
	// garage_door_triage, rolljam_lab_demo, mousejack) are deliberately NOT
	// listed here. Although their top-level summary is ours, the encoded
	// Result embeds each PhaseResult.Output verbatim (the raw sub-tool reads:
	// scanned SSIDs, NFC/NDEF records, BT device names, etc.). Those are
	// attacker-controlled — the same value a direct wifi_scan_ap / nfc_read
	// call quarantines — so the workflow must quarantine too, or it becomes a
	// prompt-injection bypass of the per-tool wrapping. They fall through to
	// the default hardware wrap.
}

// auditWrappedTools names tools that read from the audit log. Their output is
// structurally trusted (our own SQLite store) but the rows can contain
// hardware-origin content from prior turns — captured SSIDs, NFC tag URIs,
// evil-portal harvested credentials. Without wrapping, an adversarial NDEF
// payload from a previous session could launder itself into a later turn's
// instruction stream via an unwrapped audit_query result. Members get wrapped
// in <untrusted-audit-content> so the model can treat them as structured data
// with possibly-untrusted bytes inside, rather than raw live hardware bytes.
var auditWrappedTools = map[string]struct{}{
	"audit_query":         {},
	"audit_export":        {},
	"audit_stats":         {},
	"explain_last_result": {},
}

// Kind classifies a tool's quarantine policy.
type Kind int

const (
	KindNone     Kind = iota // pass through (sanitised), no wrapping
	KindAudit                // wrap in <untrusted-audit-content>
	KindHardware             // wrap in <untrusted-hardware-output>
)

// KindFor returns the quarantine policy for a tool by name.
func KindFor(toolName string) Kind {
	if _, ok := notWrappedTools[toolName]; ok {
		return KindNone
	}
	if _, ok := auditWrappedTools[toolName]; ok {
		return KindAudit
	}
	return KindHardware
}

// IsUntrustedHardwareOutput reports whether a tool gets the hardware wrapper
// specifically (audit quarantine doesn't qualify).
func IsUntrustedHardwareOutput(toolName string) bool {
	return KindFor(toolName) == KindHardware
}

// SanitizeControlChars strips ANSI CSI/C1 escape sequences and non-printable
// ASCII control bytes (preserving newline, carriage return, and tab). The
// return value is safe to embed inside a tool_result block or audit row
// without risk of terminal-control games or visual spoofing.
func SanitizeControlChars(s string) string {
	s = ansiCSIRE.ReplaceAllString(s, "")
	// Run ansiC1RE before otherControlsRE so the leading ESC byte is still
	// present when the C1 regex matches; otherwise the byte-stripper would
	// consume \x1b first and the C1 body would survive as plain text.
	s = ansiC1RE.ReplaceAllString(s, "")
	// Then strip any UNTERMINATED C1 introducer + its (rest-of-line) payload.
	s = ansiC1UntermRE.ReplaceAllString(s, "")
	s = otherControlsRE.ReplaceAllString(s, "")
	return s
}

// Output runs SanitizeControlChars on every output and, for hardware-origin
// and audit-origin tools, wraps the result in the matching untrusted-content
// delimiters regardless of whether the call succeeded or errored. Structured
// internal tools (the notWrappedTools allowlist) are sanitised but not
// wrapped.
//
// Error strings are wrapped on the same rule as successes: error messages can
// contain attacker-controlled text (e.g. an SSID embedded in a
// connection-failure message), so they must be quarantined too.
//
// The paired clause in the consuming model's system prompt tells it to treat
// content inside these tags as data, not instructions.
func Output(toolName, output string, isErr bool) string {
	_ = isErr // hardware errors carry the same risk as successes; wrap both
	sanitized := SanitizeControlChars(output)
	switch KindFor(toolName) {
	case KindNone:
		return sanitized
	case KindAudit:
		sanitized = strings.TrimRight(sanitized, " \t\r\n")
		sanitized = neutralizeCloseTag(sanitized, "untrusted-audit-content")
		return "<untrusted-audit-content>\n" + sanitized + "\n</untrusted-audit-content>"
	case KindHardware:
		fallthrough
	default:
		sanitized = strings.TrimRight(sanitized, " \t\r\n")
		sanitized = neutralizeCloseTag(sanitized, "untrusted-hardware-output")
		return "<untrusted-hardware-output>\n" + sanitized + "\n</untrusted-hardware-output>"
	}
}

// closeTagREs holds a precompiled close-tag matcher per wrapper name. The
// match is case-insensitive and tolerates whitespace immediately inside the
// tag (`</untrusted-hardware-output >`, `</untrusted-hardware-output\t>`,
// `</UNTRUSTED-HARDWARE-OUTPUT>`) — all of which a model (and a human) read as
// the closing boundary. An exact byte match would neutralize only the literal
// lowercase form and let those variants through, which is precisely the escape
// the neutralizer exists to prevent. There are exactly two wrapper names, so
// precompile both rather than build a regex per call.
var closeTagREs = map[string]*regexp.Regexp{
	"untrusted-hardware-output": regexp.MustCompile(`(?i)</\s*untrusted-hardware-output\s*>`),
	"untrusted-audit-content":   regexp.MustCompile(`(?i)</\s*untrusted-audit-content\s*>`),
}

// neutralizeCloseTag rewrites any close tag for the given wrapper name found
// inside the wrapped content to `< /NAME>` (a space after `<`). The two render
// almost identically to a human but the second is structurally NOT a close tag
// — so a smuggled close tag in an attacker-controlled SSID, NFC URI, or
// filename (in any case/whitespace variant) can't end the quarantine boundary
// prematurely. SanitizeControlChars runs before this, so a control byte hidden
// inside the tag is already gone by the time we match.
func neutralizeCloseTag(content, name string) string {
	re := closeTagREs[name]
	if re == nil {
		// Defensive: an unrecognised wrapper name should never reach here, but
		// fall back to the exact-match replacement rather than skip
		// neutralization entirely.
		return strings.ReplaceAll(content, "</"+name+">", "< /"+name+">")
	}
	return re.ReplaceAllString(content, "< /"+name+">")
}
