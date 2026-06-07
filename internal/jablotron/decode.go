// SPDX-License-Identifier: AGPL-3.0-or-later

// Package jablotron decodes the Jablotron 125 kHz LF access-control data block —
// the credential format used by Jablotron readers/fobs, widely deployed across
// Czech / Slovak / wider-EU access control and intercom systems. It recovers
// the 40-bit card data, renders the printed card number, and validates the
// 8-bit checksum. It is the offline complement to the project's other LF-RFID
// decoders (em4100_decode, fdxb_decode, ioprox_decode) and the PACS/Wiegand
// decoder (which cover HID Prox / Indala / AWID / ioProx but not Jablotron).
//
// Input is the *decoded* 64-bit (8-byte) Jablotron block — the bytes a
// demodulator such as Proxmark3's `lf jablotron demod` or a Flipper Zero LF
// read emits, MSB-first. The on-air ASK/Manchester demodulation is the reader's
// concern and out of scope here, so the decode is deterministic.
//
// # Bit layout of the 64-bit block
//
//	bits  0..15   preamble — sixteen 1 bits (0xFFFF)
//	bits 16..55   card data (40 bits / 5 bytes)
//	bits 56..63   checksum (8 bits)
//
// The checksum is  (sum of the five card-data bytes, mod 256) XOR 0x3A.
//
// The printed card number is each card-data byte read as two BCD digits
// (high nibble x10 + low nibble), the five concatenated as a base-100 decimal —
// e.g. card bytes 12 34 56 78 90 print as 1234567890. This BCD rendering is
// only meaningful when every nibble is 0..9; the raw 40-bit value is always
// surfaced so nothing is lost when the data is not BCD.
//
// # Wrap-vs-native judgement
//
//	Native. The decode is fixed bit/byte extraction plus an additive-XOR
//	checksum and a BCD render; stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The bit layout, the checksum (sum XOR 0x3A) and the BCD card-number render
//	are taken from — and agree byte-for-byte between — TWO independent
//	reference implementations: the Proxmark3 client (cmdlfjablotron.c
//	jablontron_chksum / getJablontronCardId) and the Flipper Zero firmware
//	(lib/lfrfid/protocols/protocol_jablotron.c). The 0xFFFF preamble is a hard
//	structural gate: a block without it is rejected as not-a-Jablotron-frame
//	rather than mis-decoded. The checksum is the integrity gate (surfaced as
//	crc_valid); a block that parses structurally but fails the checksum is
//	reported as such, never asserted as a real credential. When the card data
//	is not valid BCD the printed-number field is flagged and the raw value is
//	relied upon.
package jablotron

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is a decoded Jablotron credential.
type Result struct {
	Format string `json:"format"`

	CardID      uint64 `json:"card_id"`        // BCD-rendered printed number
	CardIDIsBCD bool   `json:"card_id_is_bcd"` // false => card_id render not meaningful
	RawCardHex  string `json:"raw_card_hex"`   // the 5 card-data bytes
	RawCard40   uint64 `json:"raw_card_40"`    // the 40-bit card data as a plain integer

	CRC         string `json:"crc"`
	CRCExpected string `json:"crc_expected"`
	CRCValid    bool   `json:"crc_valid"`

	RawHex string   `json:"raw_hex"`
	Notes  []string `json:"notes,omitempty"`
}

// Decode parses a 64-bit (8-byte) Jablotron block from hex (whitespace / ':' /
// '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("jablotron: need exactly 8 bytes (64-bit Jablotron block), got %d", len(b))
	}

	// Structural gate: the 16-bit preamble must be all ones.
	if binary.BigEndian.Uint16(b[0:2]) != 0xFFFF {
		return nil, fmt.Errorf("jablotron: preamble is 0x%04X, expected 0xFFFF — not a Jablotron frame", binary.BigEndian.Uint16(b[0:2]))
	}

	card := b[2:7] // 40-bit card data
	crc := b[7]

	var sum byte
	for _, x := range card {
		sum += x
	}
	calc := sum ^ 0x3A

	// Printed number: each byte as two BCD digits, base-100 concatenation.
	var cardID uint64
	isBCD := true
	for _, x := range card {
		hi, lo := x>>4, x&0x0F
		if hi > 9 || lo > 9 {
			isBCD = false
		}
		cardID = cardID*100 + uint64(hi)*10 + uint64(lo)
	}

	var raw40 uint64
	for _, x := range card {
		raw40 = raw40<<8 | uint64(x)
	}

	r := &Result{
		Format:      "Jablotron",
		CardID:      cardID,
		CardIDIsBCD: isBCD,
		RawCardHex:  strings.ToUpper(hex.EncodeToString(card)),
		RawCard40:   raw40,
		CRC:         fmt.Sprintf("0x%02X", crc),
		CRCExpected: fmt.Sprintf("0x%02X", calc),
		CRCValid:    crc == calc,
		RawHex:      strings.ToUpper(hex.EncodeToString(b)),
	}
	if !r.CRCValid {
		r.Notes = append(r.Notes, fmt.Sprintf("checksum mismatch: frame carries 0x%02X but the data computes 0x%02X — structurally a Jablotron frame but the integrity check fails (corrupt read or not a genuine credential)", crc, calc))
	}
	if !isBCD {
		r.Notes = append(r.Notes, "card data is not valid BCD (a nibble exceeds 9) — the printed card_id render is not meaningful here; use raw_card_40 / raw_card_hex")
	}
	r.Notes = append(r.Notes, "Jablotron 125 kHz LF access credential — 40-bit card data + 8-bit checksum; layout/checksum/BCD-render per the Proxmark3 and Flipper Zero references")
	return r, nil
}

// Encode builds the 64-bit (8-byte) Jablotron block from a printed card number,
// returning it as an upper-case hex string. The card number is BCD-encoded into
// the five card-data bytes (two decimal digits per byte, the inverse of the
// decoder's render), then the checksum (sum of the card bytes XOR 0x3A) and the
// 0xFFFF preamble are prepended/appended. It is the inverse of Decode:
// Decode(Encode(n)).CardID == n for any n that fits ten BCD digits.
func Encode(cardID uint64) (string, error) {
	if cardID > 9_999_999_999 {
		return "", fmt.Errorf("jablotron: card number %d exceeds the 10-digit (5-byte BCD) range", cardID)
	}
	card := make([]byte, 5)
	div := uint64(100_000_000) // 100^4
	for i := 0; i < 5; i++ {
		group := (cardID / div) % 100 // 0..99
		card[i] = byte(group/10)<<4 | byte(group%10)
		div /= 100
	}
	var sum byte
	for _, x := range card {
		sum += x
	}
	crc := sum ^ 0x3A

	b := make([]byte, 0, 8)
	b = append(b, 0xFF, 0xFF)
	b = append(b, card...)
	b = append(b, crc)
	return strings.ToUpper(hex.EncodeToString(b)), nil
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("jablotron: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("jablotron: input is not valid hex: %w", err)
	}
	return b, nil
}
