// SPDX-License-Identifier: AGPL-3.0-or-later

// Package tpms decodes TPMS (Tire Pressure Monitoring System) Sub-GHz
// bit-streams into the format-independent fields a pentester can trust:
// the Manchester line-decoded payload bytes, the 32-bit sensor ID, and
// CRC-8 validity. TPMS sensors beacon on 315 MHz (North America) and
// 433.92 MHz (Europe/Asia) and are a prime Flipper Sub-GHz target —
// they uniquely identify (and so let you track) a specific vehicle, and
// the wire format has no authentication.
//
// # Wrap-vs-native judgement
//
// Native. The hard, reusable part — recovering bytes from a
// Manchester-coded FSK/OOK bit-stream — is a public, deterministic
// transform (IEEE 802.3 and G.E. Thomas conventions). Operators bring a
// pre-demodulated bit-stream (rtl_433, a Flipper FSK Sub-GHz capture
// pre-extracted to bits, or Universal Radio Hacker) and decode offline,
// exactly as subghz_pocsag_decode does for paging.
//
// # What this package covers
//
//   - Manchester line decoding under both conventions (IEEE 802.3:
//     data 0 = "10", data 1 = "01"; G.E. Thomas: the inverse) at both
//     bit alignments, auto-selecting the convention/alignment that
//     yields the longest clean (no illegal "00"/"11" transition)
//     decode — the correct one runs clean while the wrong one trips an
//     illegal pair almost immediately.
//   - Leading-preamble tolerance: the alternating "0101…" preamble that
//     most TPMS sensors send before the payload decodes to a run of
//     data bits and is reported, not rejected.
//   - The decoded payload as hex, plus the 32-bit sensor ID — the first
//     four payload bytes, which across virtually every TPMS family is
//     the unique per-sensor identifier (the field-independent signal an
//     operator uses to fingerprint or track a vehicle).
//   - CRC-8 validity probing against the polynomials TPMS sensors
//     commonly use (0x07 CCITT, 0x2F, 0x13), reported as a
//     confidence/alignment hint.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Manufacturer-specific pressure / temperature / status field
//     interpretation: the byte offsets and scaling differ per family
//     (Schrader, Toyota, Ford, Renault, Citroën, GM, Hyundai, …) and
//     cannot be verified here without per-model captures. The raw
//     decoded bytes are surfaced so an operator can apply the relevant
//     rtl_433 model layout. Encoding this without sample data would
//     risk a confidently-wrong reading — worse than none for a security
//     tool.
//   - FSK/OOK demodulation (bring a pre-demodulated bit-stream).
//   - Differential-Manchester / biphase-mark variants used by a minority
//     of sensors (standard Manchester is the common case here).
package tpms

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a TPMS bit-stream.
type Result struct {
	InputBits       int      `json:"input_bits"`
	LineCoding      string   `json:"line_coding"`
	BitAlignment    int      `json:"bit_alignment"`
	DecodedBits     int      `json:"decoded_bits"`
	DecodedBytes    int      `json:"decoded_bytes"`
	DecodedHex      string   `json:"decoded_hex"`
	SensorID        string   `json:"sensor_id,omitempty"`
	SensorIDDecimal *uint32  `json:"sensor_id_decimal,omitempty"`
	CRC8Matches     []string `json:"crc8_matches,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

// Decode parses a TPMS Sub-GHz bit-stream (a string of '0'/'1'
// characters; ':' '-' '_' / whitespace separators tolerated).
func Decode(bitStr string) (*Result, error) {
	clean := stripSeparators(bitStr)
	if clean == "" {
		return nil, fmt.Errorf("tpms: empty bit-stream")
	}
	raw := make([]byte, 0, len(clean))
	for _, c := range clean {
		switch c {
		case '0':
			raw = append(raw, 0)
		case '1':
			raw = append(raw, 1)
		default:
			return nil, fmt.Errorf("tpms: non-binary character %q in bit-stream", string(c))
		}
	}

	// Decode under both Manchester conventions at both alignments. A
	// valid Manchester stream decodes cleanly under BOTH conventions —
	// one yields the data, the other its bitwise complement — so the
	// clean-run length only resolves the bit *alignment* (a wrong
	// alignment trips illegal "00"/"11" pairs quickly), never the
	// convention. The CRC-8 is the principled tie-breaker: the decode
	// whose trailing byte validates as a CRC over the rest is the real
	// one. When no CRC matches, the convention is genuinely ambiguous
	// and we say so.
	type scored struct {
		cand    manchesterCandidate
		payload []byte
		crc     []string
	}
	var cands []scored
	for _, ieee := range []bool{true, false} {
		for _, align := range []int{0, 1} {
			c := manchesterDecode(raw, ieee, align)
			if len(c.dataBits) < 8 {
				continue
			}
			p := packBits(c.dataBits)
			cands = append(cands, scored{cand: c, payload: p, crc: crc8Matches(p)})
		}
	}
	if len(cands) == 0 {
		return nil, fmt.Errorf("tpms: no clean Manchester decode of >= 8 data bits — wrong line coding or noise")
	}
	// Selection: prefer a CRC-validating candidate; among the chosen
	// set pick the longest; deterministic order (IEEE before G.E.
	// Thomas, align 0 before 1) breaks remaining ties via the stable
	// build order above.
	best := cands[0]
	for _, c := range cands[1:] {
		bestHasCRC := len(best.crc) > 0
		cHasCRC := len(c.crc) > 0
		switch {
		case cHasCRC && !bestHasCRC:
			best = c
		case cHasCRC == bestHasCRC && len(c.payload) > len(best.payload):
			best = c
		}
	}

	r := &Result{
		InputBits:    len(raw),
		LineCoding:   conventionName(best.cand.ieee),
		BitAlignment: best.cand.align,
		DecodedBits:  len(best.cand.dataBits),
		DecodedBytes: len(best.payload),
		DecodedHex:   strings.ToUpper(hex.EncodeToString(best.payload)),
		CRC8Matches:  best.crc,
	}
	if len(best.payload) >= 4 {
		p := best.payload
		id := uint32(p[0])<<24 | uint32(p[1])<<16 | uint32(p[2])<<8 | uint32(p[3])
		r.SensorID = strings.ToUpper(hex.EncodeToString(p[0:4]))
		r.SensorIDDecimal = &id
	} else {
		r.Notes = append(r.Notes, "payload under 4 bytes — no sensor ID extracted")
	}
	if len(best.crc) == 0 {
		r.Notes = append(r.Notes,
			"no CRC-8 match — Manchester convention is ambiguous (the other convention yields the bitwise-complement bytes, equally valid); confirm against a known sync/preamble")
	}
	r.Notes = append(r.Notes,
		"pressure / temperature / status are manufacturer-specific and not decoded; apply the rtl_433 model layout to decoded_hex")
	return r, nil
}

// manchesterCandidate is one decode attempt's result.
type manchesterCandidate struct {
	dataBits []byte
	ieee     bool
	align    int
}

// manchesterDecode decodes a Manchester-coded bit slice from the given
// alignment under the IEEE 802.3 convention (data 0 = "10", data 1 =
// "01") when ieee is true, or the G.E. Thomas convention (the inverse)
// when false. Decoding stops at the first illegal pair ("00"/"11"),
// returning the clean run decoded so far. A leading alternating
// preamble decodes cleanly to a run of identical data bits.
func manchesterDecode(raw []byte, ieee bool, align int) manchesterCandidate {
	out := make([]byte, 0, len(raw)/2)
	for i := align; i+1 < len(raw); i += 2 {
		a, b := raw[i], raw[i+1]
		switch {
		case a == 1 && b == 0: // "10"
			if ieee {
				out = append(out, 0)
			} else {
				out = append(out, 1)
			}
		case a == 0 && b == 1: // "01"
			if ieee {
				out = append(out, 1)
			} else {
				out = append(out, 0)
			}
		default: // "00" or "11" — illegal Manchester transition
			return manchesterCandidate{dataBits: out, ieee: ieee, align: align}
		}
	}
	return manchesterCandidate{dataBits: out, ieee: ieee, align: align}
}

// packBits packs data bits MSB-first into bytes, dropping a trailing
// partial byte (TPMS frames are byte-aligned).
func packBits(bitsIn []byte) []byte {
	n := len(bitsIn) / 8
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b = b<<1 | bitsIn[i*8+j]
		}
		out[i] = b
	}
	return out
}

func conventionName(ieee bool) string {
	if ieee {
		return "Manchester (IEEE 802.3: 0=10, 1=01)"
	}
	return "Manchester (G.E. Thomas: 0=01, 1=10)"
}

// crc8 polynomials TPMS sensors commonly use, by name.
var crc8Polys = []struct {
	name string
	poly byte
}{
	{"CRC-8/0x07", 0x07},
	{"CRC-8/0x2F", 0x2F},
	{"CRC-8/0x13", 0x13},
}

// crc8Matches returns the names of the CRC-8 polynomials for which the
// last payload byte equals the CRC-8 (init 0x00, no reflection) of the
// preceding bytes — a confidence/alignment hint, not a hard gate.
func crc8Matches(payload []byte) []string {
	if len(payload) < 2 {
		return nil
	}
	data := payload[:len(payload)-1]
	want := payload[len(payload)-1]
	var matches []string
	for _, p := range crc8Polys {
		if crc8(data, p.poly) == want {
			matches = append(matches, p.name)
		}
	}
	return matches
}

func crc8(data []byte, poly byte) byte {
	var crc byte
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x80 != 0 {
				crc = crc<<1 ^ poly
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

func stripSeparators(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
