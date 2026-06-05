// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dsmr decodes a DSMR / P1 smart-meter telegram — the ASCII data
// stream a Dutch/Belgian (and increasingly EU) smart electricity/gas
// meter pushes out of its P1 customer port every second. Each telegram
// is a set of OBIS-coded readings (energy import/export per tariff,
// instantaneous power, per-phase voltage/current, gas volume, outage
// counters) wrapped by an identifier line and a CRC-16. Reading the P1
// stream is the energy-side IoT data-exfiltration / monitoring surface.
//
// # Wrap-vs-native judgement
//
//	Native. A P1 telegram is fully-public ASCII (DSMR 5.0 P1
//	companion standard / IEC 62056-21): a "/IDENT" line, blank line,
//	OBIS object lines "C.D.E(value*unit)", and a trailing "!CRC".
//	The CRC is the standard CRC-16/ARC (reflected poly 0xA001, init 0)
//	over the bytes from "/" to "!" inclusive. Decoding is string
//	parsing plus that one CRC and a documented OBIS lookup table — no
//	new dependency, no shell-out; the field interpretation reference
//	parsers leave implicit is implemented here directly.
//
// # What this covers
//
//   - The meter identifier line and the CRC-16 (recomputed, reported
//     valid / invalid; CRLF line endings are normalised first so a
//     paste that lost the \r still validates).
//   - Every OBIS object line: the code, its documented meaning (energy
//     per tariff, power, per-phase voltage/current/power, outage and
//     sag/swell counters, the gas M-Bus channel, equipment IDs,
//     timestamp, …), and the parsed value + unit. Unknown OBIS codes
//     are surfaced with their raw value rather than guessed.
//
// # Deliberately deferred
//
//	The power-failure event log (1-0:99.97.0) and the timestamp DST
//	flag are surfaced as their raw values rather than fully expanded.
//	The hex-encoded equipment IDs are surfaced verbatim.
package dsmr

import (
	"fmt"
	"strings"
)

// Result is the decoded P1 telegram.
type Result struct {
	Identifier string   `json:"identifier"`
	CRC        string   `json:"crc"`
	CRCValid   bool     `json:"crc_valid"`
	Objects    []Object `json:"objects"`
	Notes      []string `json:"notes,omitempty"`
}

// Object is one decoded OBIS line.
type Object struct {
	OBIS        string `json:"obis"`
	Description string `json:"description,omitempty"`
	Value       string `json:"value,omitempty"`
	Unit        string `json:"unit,omitempty"`
	Raw         string `json:"raw"`
}

// Decode parses a DSMR P1 telegram. Line endings are tolerated in any
// form (the meter uses CRLF; a paste that normalised them is repaired
// before the CRC check).
func Decode(telegram string) (*Result, error) {
	// Normalise all line endings to CRLF for a faithful CRC.
	s := strings.ReplaceAll(telegram, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")

	start := strings.IndexByte(s, '/')
	if start < 0 {
		return nil, fmt.Errorf("no '/' identifier line found")
	}
	bang := strings.IndexByte(s[start:], '!')
	if bang < 0 {
		return nil, fmt.Errorf("no '!' end-of-telegram marker found")
	}
	bang += start

	r := &Result{}
	// CRC: the 4 hex chars immediately after '!'.
	after := s[bang+1:]
	crcStr := ""
	for i := 0; i < len(after) && i < 4; i++ {
		c := after[i]
		if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
			crcStr += string(c)
		} else {
			break
		}
	}
	if len(crcStr) == 4 {
		r.CRC = "0x" + strings.ToUpper(crcStr)
		want := crc16ARC([]byte(s[start : bang+1])) // '/'..'!' inclusive
		var got uint16
		fmt.Sscanf(crcStr, "%04x", &got)
		r.CRCValid = got == want
		if !r.CRCValid {
			r.Notes = append(r.Notes, fmt.Sprintf(
				"CRC check FAILED (telegram CRC %s, computed 0x%04X) — corrupt, truncated, or altered telegram", r.CRC, want))
		}
	} else {
		r.Notes = append(r.Notes, "no 4-hex CRC after '!' — cannot verify integrity")
	}

	lines := strings.Split(s[start:bang], "\r\n")
	for i, line := range lines {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		if i == 0 && strings.HasPrefix(line, "/") {
			r.Identifier = line[1:]
			continue
		}
		if obj, ok := parseObject(line); ok {
			r.Objects = append(r.Objects, obj)
		}
	}
	return r, nil
}

// parseObject parses one OBIS line "C-D:E.F.G(value)(value)…".
func parseObject(line string) (Object, bool) {
	paren := strings.IndexByte(line, '(')
	if paren < 0 {
		return Object{}, false
	}
	code := line[:paren]
	if !looksLikeOBIS(code) {
		return Object{}, false
	}
	body := line[paren:]
	o := Object{OBIS: code, Description: obisDescription(code), Raw: body}
	// Use the last parenthesised group as the primary value (covers the
	// gas channel's (timestamp)(value*m3) form).
	groups := parenGroups(body)
	if len(groups) > 0 {
		v := groups[len(groups)-1]
		if star := strings.IndexByte(v, '*'); star >= 0 {
			o.Value = v[:star]
			o.Unit = v[star+1:]
		} else {
			o.Value = v
		}
	}
	return o, true
}

func parenGroups(s string) []string {
	var out []string
	depth := 0
	cur := strings.Builder{}
	for _, c := range s {
		switch c {
		case '(':
			if depth == 0 {
				cur.Reset()
			} else {
				cur.WriteRune(c)
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				out = append(out, cur.String())
			} else if depth > 0 {
				cur.WriteRune(c)
			}
		default:
			if depth > 0 {
				cur.WriteRune(c)
			}
		}
	}
	return out
}

// looksLikeOBIS checks for the C-D:E.F.G shape.
func looksLikeOBIS(s string) bool {
	colon := strings.IndexByte(s, ':')
	if colon < 1 {
		return false
	}
	for _, c := range s {
		if !isOBISChar(c) {
			return false
		}
	}
	return strings.ContainsRune(s, '.')
}

func isOBISChar(c rune) bool {
	return (c >= '0' && c <= '9') || c == '-' || c == ':' || c == '.'
}
