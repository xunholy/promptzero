// SPDX-License-Identifier: AGPL-3.0-or-later

// Package rds decodes RDS / RBDS (Radio Data System) groups — the
// digital sub-carrier (57 kHz) on FM broadcast that carries the
// station's Programme Service name, RadioText, programme type, traffic
// flags and (for North American RBDS) the call sign. It is the data an
// SDR / rtl_fm + redsea pipeline pulls off any FM station, and a staple
// of broadcast-RF forensics.
//
// # Wrap-vs-native judgement
//
//	Native. RDS is fully public (IEC 62106 / NRSC-4 RBDS). A group
//	is four 16-bit blocks (A=PI, B=type+flags, C, D); the decode is
//	pure bit-field extraction plus two small lookup tables (the G0
//	character set and the programme-type names) and the RBDS
//	PI->call-sign arithmetic. No DSP and no crypto — the operator
//	pastes the post-demod block hex (redsea's `0xAAAA'BBBB'CCCC'DDDD`
//	form, or plain 16-hex-per-group) and reads the station data. No
//	new dependency, no shell-out; the reference decoder (redsea) is
//	reimplemented here, not wrapped.
//
// # What this covers
//
//   - Block A: Programme Identification (PI) code, and the RBDS
//     four-letter call sign derived from it (K/W stations).
//   - Block B: group type (0A..15B), TP (traffic-programme) flag, and
//     the 5-bit programme type with both the RDS (European) and RBDS
//     (North American) name tables.
//   - Group 0A/0B: Programme Service name (8 chars, assembled across
//     the four segments) plus the TA (traffic announcement), MS
//     (music/speech) and DI (decoder-identification) flags.
//   - Group 2A/2B: RadioText (up to 64 chars, assembled across
//     segments, truncated at the 0x0D terminator), with the A/B text
//     flag.
//   - The RDS G0 default character set (IEC 62106 Annex E) for both
//     Programme Service and RadioText.
//
// # Deliberately deferred
//
//	Clock-time (group 4A), alternative-frequency lists, Open Data
//	Applications / TMC (3A / 8A), Enhanced Other Networks (14), PIN
//	(1A), PTYN (10A) and the legacy three-letter / nationally-linked
//	RBDS call signs are not decoded; the group type is still reported
//	so nothing is silently dropped.
package rds

import (
	"fmt"
	"strings"
)

// Options controls table selection.
type Options struct {
	// RBDS selects the North American RBDS programme-type names and
	// enables PI->call-sign derivation. Default (false) uses the
	// European RDS programme-type names.
	RBDS bool
}

// Result is the decoded view of one or more RDS groups.
type Result struct {
	GroupCount       int      `json:"group_count"`
	PI               string   `json:"pi,omitempty"`
	Callsign         string   `json:"callsign,omitempty"`
	ProgrammeService string   `json:"programme_service,omitempty"`
	RadioText        string   `json:"radiotext,omitempty"`
	Groups           []Group  `json:"groups"`
	Notes            []string `json:"notes,omitempty"`
}

// Group is the decode of a single 4-block RDS group.
type Group struct {
	BlocksHex string `json:"blocks_hex"`
	PI        string `json:"pi"`
	GroupType string `json:"group_type"`
	TP        bool   `json:"tp"`
	PTY       int    `json:"pty"`
	PTYName   string `json:"pty_name"`

	// Group 0 (Programme Service)
	TA            *bool  `json:"traffic_announcement,omitempty"`
	MusicSpeech   string `json:"music_speech,omitempty"`
	DI            string `json:"decoder_identification,omitempty"`
	PSSegment     string `json:"ps_segment,omitempty"`
	PSSegmentAddr *int   `json:"ps_segment_address,omitempty"`

	// Group 2 (RadioText)
	RadioTextAB      string `json:"radiotext_ab,omitempty"`
	RadioTextSegment string `json:"radiotext_segment,omitempty"`

	Note string `json:"note,omitempty"`
}

// Decode parses a sequence of RDS groups from hex. Each group is four
// 16-bit blocks (16 hex digits); the redsea `0x….'….'….'….` form, plain
// concatenated hex, and ':'/'-'/'_'/whitespace/comma separators are all
// accepted.
func Decode(hexStr string, opts Options) (*Result, error) {
	clean := stripSeparators(hexStr)
	if clean == "" {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%16 != 0 {
		return nil, fmt.Errorf("input must be a whole number of 16-hex-digit groups (4 blocks each); got %d hex digits", len(clean))
	}

	r := &Result{}
	var ps [8]byte
	for i := range ps {
		ps[i] = ' '
	}
	psSet := false
	rt := make([]byte, 64)
	for i := range rt {
		rt[i] = ' '
	}
	rtSet := false
	var lastPI string

	for off := 0; off < len(clean); off += 16 {
		blocks, err := parseBlocks(clean[off : off+16])
		if err != nil {
			return nil, fmt.Errorf("group %d: %w", off/16, err)
		}
		g := decodeGroup(blocks, opts, &ps, &psSet, rt, &rtSet)
		r.Groups = append(r.Groups, g)
		lastPI = g.PI
	}
	r.GroupCount = len(r.Groups)
	r.PI = lastPI
	if opts.RBDS && lastPI != "" {
		if cs := callsignFromPIHex(lastPI); cs != "" {
			r.Callsign = cs
		}
	}
	if psSet {
		r.ProgrammeService = renderText(ps[:])
	}
	if rtSet {
		r.RadioText = renderText(truncateAtCR(rt))
	}
	return r, nil
}

func parseBlocks(h string) ([4]uint16, error) {
	var b [4]uint16
	for i := 0; i < 4; i++ {
		var v uint16
		for j := 0; j < 4; j++ {
			c := h[i*4+j]
			d, ok := hexNibble(c)
			if !ok {
				return b, fmt.Errorf("invalid hex digit %q", c)
			}
			v = v<<4 | uint16(d)
		}
		b[i] = v
	}
	return b, nil
}

func decodeGroup(b [4]uint16, opts Options, ps *[8]byte, psSet *bool, rt []byte, rtSet *bool) Group {
	bA, bB, bC, bD := b[0], b[1], b[2], b[3]
	typeNum := int(bB>>12) & 0xF
	version := int(bB>>11) & 1 // 0=A, 1=B
	verCh := "A"
	if version == 1 {
		verCh = "B"
	}
	pty := int(bB>>5) & 0x1F
	g := Group{
		BlocksHex: fmt.Sprintf("%04X%04X%04X%04X", bA, bB, bC, bD),
		PI:        fmt.Sprintf("0x%04X", bA),
		GroupType: fmt.Sprintf("%d%s", typeNum, verCh),
		TP:        bB&0x0400 != 0,
		PTY:       pty,
		PTYName:   ptyName(pty, opts.RBDS),
	}

	switch typeNum {
	case 0: // 0A / 0B — Programme Service name + flags
		seg := int(bB) & 0x3 // PS segment address is in block B bits 0-1
		ta := bB&0x0010 != 0
		g.TA = &ta
		if bB&0x0008 != 0 {
			g.MusicSpeech = "music"
		} else {
			g.MusicSpeech = "speech"
		}
		g.DI = diLabel(seg, bB&0x0004 != 0)
		// PS chars: block D high + low byte at position seg*2.
		hi, lo := byte(bD>>8), byte(bD&0xFF)
		ps[seg*2] = hi
		ps[seg*2+1] = lo
		*psSet = true
		s := seg
		g.PSSegmentAddr = &s
		g.PSSegment = renderText([]byte{hi, lo})
	case 2: // 2A / 2B — RadioText
		seg := int(bB) & 0xF
		if bB&0x0010 != 0 {
			g.RadioTextAB = "B"
		} else {
			g.RadioTextAB = "A"
		}
		if version == 0 { // 2A: 4 chars from C and D
			pos := seg * 4
			chars := []byte{byte(bC >> 8), byte(bC & 0xFF), byte(bD >> 8), byte(bD & 0xFF)}
			for i, c := range chars {
				if pos+i < len(rt) {
					rt[pos+i] = c
				}
			}
			g.RadioTextSegment = renderText(chars)
		} else { // 2B: 2 chars from D
			pos := seg * 2
			chars := []byte{byte(bD >> 8), byte(bD & 0xFF)}
			for i, c := range chars {
				if pos+i < len(rt) {
					rt[pos+i] = c
				}
			}
			g.RadioTextSegment = renderText(chars)
		}
		*rtSet = true
	default:
		g.Note = "group type decoded at the header level only (PS/RadioText/PI/PTY); " +
			"this type's payload is not yet broken out"
	}
	return g
}

// truncateAtCR returns the RadioText buffer up to the first 0x0D
// carriage-return terminator (IEC 62106 §3.1.5.3).
func truncateAtCR(rt []byte) []byte {
	for i, c := range rt {
		if c == 0x0D {
			return rt[:i]
		}
	}
	return rt
}

// renderText maps raw RDS bytes through the G0 character set and trims
// trailing blanks.
func renderText(raw []byte) string {
	var sb strings.Builder
	for _, b := range raw {
		sb.WriteString(g0Charset[b])
	}
	return strings.TrimRight(sb.String(), " ")
}

func diLabel(segment int, set bool) string {
	// DI is signalled one bit per 0A segment (IEC 62106 §3.1.5.2).
	names := map[int]string{0: "dynamic_pty", 1: "compressed", 2: "artificial_head", 3: "stereo"}
	name := names[segment]
	if name == "" {
		return ""
	}
	return fmt.Sprintf("%s=%t", name, set)
}

func ptyName(pty int, rbds bool) string {
	if pty < 0 || pty >= 32 {
		return "Unknown"
	}
	if rbds {
		return ptyNamesRBDS[pty]
	}
	return ptyNamesRDS[pty]
}

// callsignFromPIHex derives the RBDS four-letter call sign from a PI code
// rendered as "0xNNNN". Returns "" for PI codes outside the four-letter
// K/W range (the legacy three-letter and nationally-linked tables are
// deliberately not implemented).
func callsignFromPIHex(piHex string) string {
	var pi uint16
	if _, err := fmt.Sscanf(piHex, "0x%04X", &pi); err != nil {
		return ""
	}
	if pi < 0x1000 || pi > 0x994F {
		return ""
	}
	var prefix byte
	if pi <= 0x54A7 {
		prefix = 'K'
		pi -= 0x1000
	} else {
		prefix = 'W'
		pi -= 0x54A8
	}
	const n = 26
	return string([]byte{
		prefix,
		'A' + byte((int(pi)/(n*n))%n),
		'A' + byte((int(pi)/n)%n),
		'A' + byte(int(pi)%n),
	})
}

func stripSeparators(s string) string {
	var sb strings.Builder
	i := 0
	for i < len(s) {
		// drop a "0x"/"0X" prefix wherever it appears (per-group in the
		// redsea form).
		if i+1 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
			i += 2
			continue
		}
		c := s[i]
		switch c {
		case ':', '-', '_', '\'', ' ', '\t', '\n', '\r', ',':
		default:
			sb.WriteByte(c)
		}
		i++
	}
	return sb.String()
}

func hexNibble(c byte) (int, bool) {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0'), true
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10, true
	}
	return 0, false
}
