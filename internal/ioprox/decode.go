// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ioprox decodes the IO Prox (Kantech XSF) 125 kHz LF access-control
// data block — the credential format used by Kantech ioProx readers, widely
// deployed across North American commercial / institutional access control. It
// recovers the facility code, the version byte, the 16-bit card number, and
// validates the 8-bit checksum. It is the offline complement to the project's
// other LF-RFID decoders (em4100_decode, fdxb_decode) and the PACS/Wiegand
// decoder (internal/pacs), which cover HID Prox / Indala / AWID but not ioProx.
//
// Input is the *decoded* 64-bit (8-byte) IO Prox block — the bytes a
// demodulator such as Proxmark3's `lf io demod` or a Flipper Zero LF read emits
// (the "Raw" value), MSB-first. The on-air FSK demodulation is the reader's
// concern and is out of scope here: this package decodes the data block, not
// the raw RF, so its output is deterministic and independently verifiable.
//
// # Bit layout of the 64-bit block
//
//	bits  0..8    nine zero preamble bits
//	bits  9..16   fixed marker 0xF0
//	bit   17      separator (1)
//	bits 18..25   facility code (8 bits)
//	bit   26      separator (1)
//	bits 27..34   version (8 bits)
//	bit   35      separator (1)
//	bits 36..43   card number high byte (8 bits)
//	bit   44      separator (1)
//	bits 45..52   card number low byte (8 bits)
//	bit   53      separator (1)
//	bits 54..61   checksum (8 bits)
//	bits 62..63   two trailing separator bits (1,1)
//
// The checksum is  0xFF - ((0xF0 + facility + version + cardHi + cardLo) mod
// 256)  — i.e. it spans the five 8-bit fields at 9-bit intervals, including the
// 0xF0 marker.
//
// # Wrap-vs-native judgement
//
//	Native. The decode is fixed bit extraction at known offsets plus an 8-bit
//	additive checksum; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The bit layout and the checksum algorithm are taken from — and agree
//	byte-for-byte between — TWO independent reference implementations: the
//	Proxmark3 client (cmdlfio.c getIOProxBits / the XSF demod) and the Flipper
//	Zero firmware (lib/lfrfid/protocols/protocol_io_prox_xsf.c). The structural
//	frame (nine zero preamble bits, the 0xF0 marker, the six separator '1'
//	bits) is a hard gate: a block whose marker or separators do not match is
//	rejected as not-an-ioProx-frame rather than mis-decoded. The checksum is
//	the integrity gate and is surfaced as crc_valid; a block that parses
//	structurally but fails the checksum is reported as such, never asserted as
//	a real credential.
package ioprox

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is a decoded IO Prox (Kantech XSF) credential.
type Result struct {
	Format       string `json:"format"`
	Version      int    `json:"version"`
	FacilityCode int    `json:"facility_code"`
	CardNumber   int    `json:"card_number"`
	XSF          string `json:"xsf"`
	CRC          string `json:"crc"`
	CRCExpected  string `json:"crc_expected"`
	CRCValid     bool   `json:"crc_valid"`

	RawHex string   `json:"raw_hex"`
	Notes  []string `json:"notes,omitempty"`
}

// Decode parses a 64-bit (8-byte) IO Prox block from hex (whitespace / ':' /
// '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("ioprox: need exactly 8 bytes (64-bit IO Prox block), got %d", len(b))
	}

	// Structural gate: nine zero preamble bits + the 0xF0 marker + the six
	// framing '1' separators. A frame that fails this is not IO Prox.
	if getBits(b, 0, 8) != 0x00 || getBits(b, 8, 1) != 0 {
		return nil, fmt.Errorf("ioprox: preamble is not nine zero bits — not an IO Prox frame")
	}
	if getBits(b, 9, 8) != 0xF0 {
		return nil, fmt.Errorf("ioprox: marker byte is 0x%02X, expected 0xF0 — not an IO Prox frame", getBits(b, 9, 8))
	}
	for _, p := range []int{17, 26, 35, 44, 53, 62, 63} {
		if getBits(b, p, 1) != 1 {
			return nil, fmt.Errorf("ioprox: framing separator bit at position %d is not 1 — not an IO Prox frame", p)
		}
	}

	facility := getBits(b, 18, 8)
	version := getBits(b, 27, 8)
	cardHi := getBits(b, 36, 8)
	cardLo := getBits(b, 45, 8)
	crc := getBits(b, 54, 8)

	// Checksum: 0xFF - sum of the five 8-bit fields at 9-bit intervals
	// (0xF0 marker, facility, version, cardHi, cardLo), modulo 256.
	calc := byte(0xFF - (0xF0 + facility + version + cardHi + cardLo))
	card := int(cardHi)<<8 | int(cardLo)

	r := &Result{
		Format:       "IO Prox XSF (Kantech)",
		Version:      int(version),
		FacilityCode: int(facility),
		CardNumber:   card,
		// Proxmark renders the label as XSF(version)facility:card with the
		// facility code in HEX; reproduced here for ecosystem familiarity,
		// while facility_code above is the plain decimal value.
		XSF:         fmt.Sprintf("XSF(%02d)%02x:%05d", version, facility, card),
		CRC:         fmt.Sprintf("0x%02X", crc),
		CRCExpected: fmt.Sprintf("0x%02X", calc),
		CRCValid:    crc == calc,
		RawHex:      strings.ToUpper(hex.EncodeToString(b)),
	}
	if !r.CRCValid {
		r.Notes = append(r.Notes, fmt.Sprintf("checksum mismatch: frame carries 0x%02X but the data computes 0x%02X — structurally an IO Prox frame but the integrity check fails (corrupt read or not a genuine credential)", crc, calc))
	}
	r.Notes = append(r.Notes, "IO Prox (Kantech XSF) 125 kHz LF access credential — facility code + version + 16-bit card number; layout/checksum per the Proxmark3 and Flipper Zero references")
	return r, nil
}

// Encode builds the 64-bit (8-byte) IO Prox block from a facility code, version
// and 16-bit card number, returning it as an upper-case hex string. It is the
// inverse of Decode: Decode(Encode(...)) reproduces the inputs with a valid
// checksum. The checksum is recomputed (0xFF - (0xF0 + facility + version +
// cardHi + cardLo)), so the emitted block always carries a correct CRC.
func Encode(facility, version byte, card uint16) string {
	b := make([]byte, 8)
	setBits(b, 9, 8, 0xF0) // marker
	// framing separator bits
	for _, p := range []int{17, 26, 35, 44, 53, 62, 63} {
		setBits(b, p, 1, 1)
	}
	cardHi := byte(card >> 8)
	cardLo := byte(card)
	setBits(b, 18, 8, facility)
	setBits(b, 27, 8, version)
	setBits(b, 36, 8, cardHi)
	setBits(b, 45, 8, cardLo)
	crc := byte(0xFF - (0xF0 + facility + version + cardHi + cardLo))
	setBits(b, 54, 8, crc)
	return strings.ToUpper(hex.EncodeToString(b))
}

// setBits writes the low n bits of v (MSB-first) starting at bit position pos.
func setBits(b []byte, pos, n int, v byte) {
	for i := 0; i < n; i++ {
		bit := (v >> uint(n-1-i)) & 1
		idx := pos + i
		mask := byte(1) << (7 - uint(idx%8))
		if bit == 1 {
			b[idx/8] |= mask
		} else {
			b[idx/8] &^= mask
		}
	}
}

// getBits reads n bits (MSB-first) starting at bit position pos from b.
func getBits(b []byte, pos, n int) byte {
	var v byte
	for i := 0; i < n; i++ {
		bit := pos + i
		v = (v << 1) | ((b[bit/8] >> (7 - uint(bit%8))) & 1)
	}
	return v
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("ioprox: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ioprox: input is not valid hex: %w", err)
	}
	return b, nil
}
