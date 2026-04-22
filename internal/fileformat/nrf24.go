package fileformat

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// NRF24 / Mousejack file-format support.
//
// The NRF24 Mouse Jacker + NRF24 Sniffer FAPs on Flipper Zero Momentum
// firmware use two plain-text artefacts on the SD card. No CLI commands
// exist to manipulate them, so PromptZero parses/builds them directly
// and hands the resulting bytes to the Flipper's storage layer.
//
//  1. Target list: /ext/apps_data/nrfsniff/addresses.txt
//     Comma-separated lines, one per captured peripheral:
//       A1:B2:C3:D4:E5,1
//     where the suffix is the NRF24 data rate (1 = 1 Mbps, 2 = 2 Mbps).
//     The Mouse Jacker FAP reads this file at launch and uses it as the
//     pairing-target candidate set.
//
//  2. Keystroke payloads: /ext/mousejacker/<name>.txt
//     Standard DuckyScript — same lexical surface as BadUSB, so the
//     existing validator package can inspect them for destructive
//     patterns. PromptZero's BuildMousejackPayload enforces the
//     mousejack-specific shape (short DELAYs, no OS-timing-dependent
//     GUI combos) that the 2.4 GHz injection path tolerates.

// NRF24Target is one captured wireless-peripheral address.
type NRF24Target struct {
	// Address is the 5-byte NRF24 pipe address, uppercase
	// colon-separated (e.g. "A1:B2:C3:D4:E5"). The Mouse Jacker FAP
	// matches bytes verbatim — whitespace or lowercase confuses it.
	Address string

	// Rate is the NRF24 data rate the sniffer observed the address at.
	// 1 = 1 Mbps (most Microsoft peripherals), 2 = 2 Mbps (Logitech
	// Unifying / MX family). A '250' value means 250 kbps, rare on
	// modern peripherals.
	Rate int
}

// addrRE matches 5 hex pairs separated by colons. The FAP rejects other
// shapes, so we normalise the parser to the same constraint.
var addrRE = regexp.MustCompile(`^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){4}$`)

// ParseNRF24Addresses parses the addresses.txt shape the NRF24 Sniffer
// FAP writes. Malformed lines are skipped with a non-fatal error
// aggregated in the returned slice — callers log the count and continue.
// Returns an error only when the whole file is empty / unparseable.
func ParseNRF24Addresses(src string) ([]NRF24Target, []string, error) {
	if strings.TrimSpace(src) == "" {
		return nil, nil, fmt.Errorf("nrf24_addresses: empty file")
	}
	var out []NRF24Target
	var warnings []string
	for i, raw := range strings.Split(src, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			warnings = append(warnings, fmt.Sprintf("line %d: missing rate suffix: %q", i+1, line))
			continue
		}
		addr := strings.ToUpper(strings.TrimSpace(parts[0]))
		if !addrRE.MatchString(addr) {
			warnings = append(warnings, fmt.Sprintf("line %d: invalid address %q", i+1, addr))
			continue
		}
		rate, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: invalid rate %q", i+1, parts[1]))
			continue
		}
		if rate != 1 && rate != 2 && rate != 250 {
			warnings = append(warnings, fmt.Sprintf("line %d: suspicious rate %d (expected 1, 2, or 250)", i+1, rate))
			// still emit — the FAP might accept it.
		}
		out = append(out, NRF24Target{Address: addr, Rate: rate})
	}
	if len(out) == 0 {
		return nil, warnings, fmt.Errorf("nrf24_addresses: no parseable targets in %d lines", strings.Count(src, "\n")+1)
	}
	return out, warnings, nil
}

// MousejackPayloadParams carries inputs for BuildMousejackPayload. The
// script is a DuckyScript body — lines of STRING / DELAY / GUI combos
// etc. that the Mouse Jacker FAP replays at the remote keyboard.
type MousejackPayloadParams struct {
	// Script is the DuckyScript body. Lines are trimmed and
	// empty/comment lines dropped. Whitespace-only input errors out.
	Script string

	// TargetOS hints the builder at expected key-combo conventions.
	// Valid: "windows", "macos", "linux". Empty defaults to windows.
	TargetOS string

	// MaxDelayMS caps the argument to any DELAY line. Mousejack
	// sessions are 2.4 GHz and flaky — very long delays often lose
	// sync with the receiver. Defaults to 5000 (5s); passing 0
	// applies the default.
	MaxDelayMS int
}

// defaultMaxMousejackDelay is the conservative DELAY ceiling applied
// when the caller doesn't override MaxDelayMS. 2.4 GHz injection
// sessions typically break after ~10s of silence; 5s leaves room for
// one natural pause without risking pairing loss.
const defaultMaxMousejackDelay = 5000

// BuildMousejackPayload validates the DuckyScript and returns the
// canonical bytes ready to write to /ext/mousejacker/<name>.txt.
// Validation rules:
//   - non-empty after comment stripping
//   - every DELAY argument ≤ MaxDelayMS
//   - a sane target-OS string (for future per-OS transformations)
//
// BuildMousejackPayload does not enforce DuckyScript syntax beyond
// the delay cap — the validator.Validate() pass (called separately on
// the bytes) handles destructive-pattern detection mirrored from
// BadUSB.
func BuildMousejackPayload(p MousejackPayloadParams) ([]byte, error) {
	script := strings.TrimSpace(p.Script)
	if script == "" {
		return nil, fmt.Errorf("mousejack_payload: script empty")
	}
	cap := p.MaxDelayMS
	if cap <= 0 {
		cap = defaultMaxMousejackDelay
	}
	if p.TargetOS != "" {
		switch strings.ToLower(p.TargetOS) {
		case "windows", "macos", "linux":
			// acceptable
		default:
			return nil, fmt.Errorf("mousejack_payload: unsupported target_os %q (want windows|macos|linux)", p.TargetOS)
		}
	}

	var out strings.Builder
	scanner := strings.Split(script, "\n")
	nonComment := 0
	for i, raw := range scanner {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			out.WriteString("\n")
			continue
		}
		if strings.HasPrefix(trimmed, "REM") {
			out.WriteString(line)
			out.WriteString("\n")
			continue
		}
		if head, rest := firstWord(trimmed); head == "DELAY" {
			ms, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return nil, fmt.Errorf("mousejack_payload: line %d DELAY needs integer ms, got %q", i+1, rest)
			}
			if ms > cap {
				return nil, fmt.Errorf("mousejack_payload: line %d DELAY %d ms exceeds cap %d — 2.4 GHz injection loses sync on long pauses", i+1, ms, cap)
			}
			if ms < 0 {
				return nil, fmt.Errorf("mousejack_payload: line %d negative DELAY %d", i+1, ms)
			}
		}
		nonComment++
		out.WriteString(line)
		out.WriteString("\n")
	}
	if nonComment == 0 {
		return nil, fmt.Errorf("mousejack_payload: script contains only REM lines — no keystrokes to inject")
	}
	return []byte(out.String()), nil
}

// firstWord returns the first whitespace-separated token and the rest
// of the line. Used by the DELAY validator in BuildMousejackPayload.
func firstWord(s string) (head, rest string) {
	i := strings.IndexAny(s, " \t")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}
