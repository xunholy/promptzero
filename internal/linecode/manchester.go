// SPDX-License-Identifier: AGPL-3.0-or-later

// Package linecode decodes raw line-code bitstreams into the data bits they
// carry. It is the reverse-engineering layer between a raw capture and the
// protocol decoders: when bringing up a decoder for an unknown OOK/FSK or
// RFID bitstream, "is this Manchester, and if so what's the data?" is a
// constant first question, and doing it by hand is error-prone.
//
// # Wrap-vs-native judgement
//
// Native. Manchester is a fixed bi-phase mapping over bit pairs; decoding is a
// pair walk with a validity check. The project already does this inline inside
// several protocol decoders (em4100, z-wave, m-bus, weather, tpms); this
// exposes it as a reusable RE primitive.
//
// # Verifiable / no confidently-wrong output
//
// Valid Manchester contains only the bit pairs 01 and 10 — a 00 or 11 pair is
// illegal — so a non-Manchester (or mis-aligned) stream is flagged by its
// invalid pairs rather than mis-decoded. The two naming conventions (IEEE
// 802.3 and G.E. Thomas) invert each other, an ambiguity that cannot be
// resolved from the bits alone, so BOTH decodes are returned and the operator
// (who knows the protocol) picks — never a silent guess. Both bit alignments
// (starting at bit 0 or skipping a leading half-bit) are tried, and the
// fully-valid alignment(s) are highlighted — the RE hint.
//
// # Covered / deferred
//
// Covered: standard Manchester, both conventions, both alignments, with a
// validity gate. Differential Manchester / biphase-mark-space (stateful) and
// NRZI are deliberately deferred.
package linecode

import (
	"fmt"
	"strings"
)

// ManchesterCandidate is one decode attempt at a given bit alignment.
type ManchesterCandidate struct {
	Alignment    int    `json:"alignment"` // 0 = from the first bit, 1 = skipping a leading half-bit
	Valid        bool   `json:"valid"`     // all pairs were 01 or 10
	InvalidPairs []int  `json:"invalid_pairs,omitempty"`
	IEEE8023     string `json:"ieee_802_3"` // 10->1, 01->0
	Thomas       string `json:"thomas"`     // 01->1, 10->0 (G.E. Thomas)
}

// ManchesterResult holds the candidate decodes for both alignments.
type ManchesterResult struct {
	InputBits  int                   `json:"input_bits"`
	Candidates []ManchesterCandidate `json:"candidates"`
	Notes      []string              `json:"notes,omitempty"`
}

// DecodeManchester decodes a raw '0'/'1' bitstream as standard Manchester,
// trying both bit alignments and returning both convention mappings.
func DecodeManchester(bits string) (*ManchesterResult, error) {
	clean := strings.NewReplacer(" ", "", "_", "", "-", "", "\n", "", "\t", "").Replace(strings.TrimSpace(bits))
	if clean == "" {
		return nil, fmt.Errorf("linecode: empty bitstream")
	}
	for i := 0; i < len(clean); i++ {
		if clean[i] != '0' && clean[i] != '1' {
			return nil, fmt.Errorf("linecode: character %q at position %d is not '0'/'1'", string(clean[i]), i)
		}
	}

	res := &ManchesterResult{InputBits: len(clean)}
	validAlignments := []int{}
	for _, align := range []int{0, 1} {
		s := clean[align:]
		var ieee, thomas strings.Builder
		var invalid []int
		for i := 0; i+1 < len(s); i += 2 {
			pair := s[i : i+2]
			switch pair {
			case "10":
				ieee.WriteByte('1')
				thomas.WriteByte('0')
			case "01":
				ieee.WriteByte('0')
				thomas.WriteByte('1')
			default: // 00 or 11 — illegal in Manchester
				ieee.WriteByte('?')
				thomas.WriteByte('?')
				invalid = append(invalid, align+i)
			}
		}
		c := ManchesterCandidate{
			Alignment:    align,
			Valid:        len(invalid) == 0 && ieee.Len() > 0,
			InvalidPairs: invalid,
			IEEE8023:     ieee.String(),
			Thomas:       thomas.String(),
		}
		res.Candidates = append(res.Candidates, c)
		if c.Valid {
			validAlignments = append(validAlignments, align)
		}
	}

	switch len(validAlignments) {
	case 0:
		res.Notes = append(res.Notes, "no alignment yields fully-valid Manchester (every alignment has illegal 00/11 pairs) — the stream is likely not Manchester, or is noisy/truncated")
	case 2:
		res.Notes = append(res.Notes, "both alignments are valid Manchester — the stream is ambiguous on framing; the intended one depends on the protocol's preamble")
	default:
		res.Notes = append(res.Notes, fmt.Sprintf("alignment %d produces fully-valid Manchester — the likely framing; pick the IEEE-802.3 or Thomas column per the protocol's convention", validAlignments[0]))
	}
	return res, nil
}

// EncodeManchesterIEEE renders data bits as an IEEE-802.3 Manchester stream
// (0 -> "01", 1 -> "10") — the inverse of the IEEE column, for round-tripping.
func EncodeManchesterIEEE(data string) string {
	var b strings.Builder
	for i := 0; i < len(data); i++ {
		if data[i] == '1' {
			b.WriteString("10")
		} else {
			b.WriteString("01")
		}
	}
	return b.String()
}
