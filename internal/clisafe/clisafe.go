// Package clisafe contains helpers shared by every transport that pushes
// operator-supplied strings through a line-oriented CLI. Moving these out
// of flipper/ and marauder/ makes fixes land once, and is a prerequisite
// for future BLE / MCP transports that will need the same guarantees.
package clisafe

import "strings"

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
