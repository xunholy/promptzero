// Package clisafe contains helpers shared by every transport that pushes
// operator-supplied strings through a line-oriented CLI. Moving these out
// of flipper/ and marauder/ makes fixes land once, and is a prerequisite
// for future BLE / MCP transports that will need the same guarantees.
package clisafe

import (
	"strings"
	"unicode/utf8"
)

// EllipsisMarker is the suffix appended by TruncateWithEllipsis. Exported
// so callers comparing against truncation output (tests, downstream
// renderers) don't have to repeat the literal.
const EllipsisMarker = "…"

// TruncateWithEllipsis returns s unchanged when len(s) <= n. Otherwise
// it cuts s at the largest valid UTF-8 boundary at or before n and
// appends EllipsisMarker.
//
// Pre-extraction the codebase had 15 inline copies of this walk-back
// loop in evilportal, badusb-validator, agent (handoff/verify/session),
// generate, report, audit, rag, consensus. Each had drifted slightly:
// some forgot the `cut <= 0` guard, some omitted the ellipsis, one
// used 0xC0 != 0x80 (inverted condition). One shared helper keeps the
// safety invariant in one place — output is always valid UTF-8 — and
// the marker length is consistent across the UI.
//
// n <= 0 returns just the marker (callers that pass 0 typically want
// "anything truncated here is too long to show"); negative n is
// clamped the same way.
func TruncateWithEllipsis(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 0 {
		return EllipsisMarker
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + EllipsisMarker
}

// SanitizeArg strips bytes that would terminate or break out of a single
// CLI command line when interpolated: CR, LF, NUL, ETX (Ctrl+C), and the
// double-quote we use as a delimiter on quoted Marauder fields.
//
// The scrubbed set is the union of what flipper and marauder have stripped
// historically — keeping one helper means a new escape byte only has to be
// added once.
func SanitizeArg(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\x00', '\x03', '"':
			return -1
		}
		return r
	}, s)
}
