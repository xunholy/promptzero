// Package wordlists embeds PromptZero's built-in wordlists and exposes them
// as MCP resources via promptzero://wordlists/<name> URIs.
//
// # Wordlist provenance
//
//   - common.txt  — ~500-entry HTTP path list assembled from public-domain
//     and CC0 sources (RFC 8615 well-known URIs, nginx/Apache default paths,
//     IETF/W3C standardised paths). Licensed CC0-1.0.
//   - passwords.txt — ~100-entry common-password list assembled from
//     publicly-published top-N studies and policy documentation examples.
//     Licensed CC0-1.0.
//
// Both wordlists are safe to embed under PromptZero's AGPL-3.0-or-later
// license. Provenance comments are in each .txt file's header.
package wordlists

import (
	_ "embed"
	"strings"
)

//go:embed common.txt
var commonTxt string

//go:embed passwords.txt
var passwordsTxt string

// Common returns the lines of the built-in HTTP common-paths wordlist.
// Comment lines (beginning with '#') and blank lines are stripped.
func Common() []string {
	return parseLines(commonTxt)
}

// Passwords returns the lines of the built-in common-passwords wordlist.
// Comment lines (beginning with '#') and blank lines are stripped.
func Passwords() []string {
	return parseLines(passwordsTxt)
}

// CommonRaw returns the raw embedded text of common.txt (comments included).
// Used by the MCP resource handler to serve the file verbatim.
func CommonRaw() string {
	return commonTxt
}

// PasswordsRaw returns the raw embedded text of passwords.txt (comments included).
// Used by the MCP resource handler to serve the file verbatim.
func PasswordsRaw() string {
	return passwordsTxt
}

// parseLines splits raw embedded text into non-empty, non-comment lines.
func parseLines(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
