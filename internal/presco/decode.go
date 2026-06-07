// SPDX-License-Identifier: AGPL-3.0-or-later

// Package presco decodes the Presco 125 kHz LF access-control data block — the
// credential format used by Presco readers (gate / garage / building access).
// It recovers the 32-bit full code and the Proxmark-style site / user codes
// derived from it. It is the offline complement to the project's other LF-RFID
// decoders (em4100_decode, fdxb_decode, ioprox_decode, jablotron_decode,
// viking_decode, noralsy_decode) and the PACS/Wiegand decoder.
//
// Input is the *decoded* 128-bit (16-byte) Presco block — the bytes a
// demodulator such as Proxmark3's `lf presco demod` emits, MSB-first. The
// on-air ASK demodulation is the reader's concern and out of scope here, so the
// decode is deterministic.
//
// # Bit layout of the 128-bit block (four 32-bit words)
//
//	bits   0..31   preamble 0x10D00000
//	bits  32..63   0x00000000
//	bits  64..95   0x00000000
//	bits  96..127  full code (32 bits)
//
// From the full code: site code = (full >> 24) & 0xFF, user code = full & 0xFFFF
// (the Proxmark-style derivation; the 32-bit full code is the primary value).
//
// # Wrap-vs-native judgement
//
//	Native. The decode is a fixed structural gate plus a 32-bit field read;
//	stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The layout is taken from the Proxmark3 client (cmdlfpresco.c) — both its
//	encoder (getPrescoBits: 0x10D00000, two zero words, then the full code) and
//	its decoder (detectPresco + the site/user extraction), which are inverse and
//	so internally cross-check. Presco is a SINGLE-reference format here (the
//	Flipper Zero mainline firmware does not implement it), and it carries NO
//	checksum — so integrity rests entirely on the 96-bit structural gate
//	(preamble 0x10D00000 + two zero words, a ~1-in-2^96 marker): a block that
//	fails the gate is rejected as not-a-Presco-frame rather than mis-decoded.
//	The 32-bit full code is the unambiguous primary value (literally the final
//	word after the gate); the site / user codes are surfaced as the Proxmark
//	derivation of it.
package presco

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is a decoded Presco credential.
type Result struct {
	Format string `json:"format"`

	FullCode    uint32 `json:"full_code"`
	FullCodeHex string `json:"full_code_hex"`
	SiteCode    int    `json:"site_code"`
	UserCode    int    `json:"user_code"`

	RawHex string   `json:"raw_hex"`
	Notes  []string `json:"notes,omitempty"`
}

const preamble = 0x10D00000

// Decode parses a 128-bit (16-byte) Presco block from hex (whitespace / ':' /
// '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) != 16 {
		return nil, fmt.Errorf("presco: need exactly 16 bytes (128-bit Presco block), got %d", len(b))
	}

	w0 := binary.BigEndian.Uint32(b[0:4])
	w1 := binary.BigEndian.Uint32(b[4:8])
	w2 := binary.BigEndian.Uint32(b[8:12])
	full := binary.BigEndian.Uint32(b[12:16])

	// Structural gate: preamble + two zero words (the only integrity gate —
	// Presco carries no checksum).
	if w0 != preamble {
		return nil, fmt.Errorf("presco: preamble word is 0x%08X, expected 0x%08X — not a Presco frame", w0, preamble)
	}
	if w1 != 0 || w2 != 0 {
		return nil, fmt.Errorf("presco: words 2/3 are 0x%08X/0x%08X, expected zero — not a Presco frame", w1, w2)
	}

	r := &Result{
		Format:      "Presco",
		FullCode:    full,
		FullCodeHex: fmt.Sprintf("%08X", full),
		SiteCode:    int((full >> 24) & 0xFF),
		UserCode:    int(full & 0xFFFF),
		RawHex:      strings.ToUpper(hex.EncodeToString(b)),
	}
	r.Notes = append(r.Notes,
		"Presco carries no checksum — integrity rests on the 96-bit structural gate (preamble 0x10D00000 + two zero words)",
		"the 32-bit full_code is the primary value; site_code / user_code are the Proxmark derivation (full>>24 & 0xFF, full & 0xFFFF)",
		"Presco 125 kHz LF access credential — layout per the Proxmark3 reference (single reference: Flipper mainline does not implement Presco)")
	return r, nil
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("presco: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("presco: input is not valid hex: %w", err)
	}
	return b, nil
}
