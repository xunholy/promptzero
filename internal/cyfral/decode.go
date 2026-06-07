// SPDX-License-Identifier: AGPL-3.0-or-later

// Package cyfral decodes a Cyfral iButton frame — the contact-key format used by
// Cyfral intercom systems (common across the former-CIS / Eastern-European
// residential market). It is the second of the two non-Dallas iButton formats
// the project's internal/ibutton decoder deferred (the first, Metakom, is
// internal/metakom).
//
// # Why the on-wire frame, not the 2-byte ID
//
// A Cyfral key decodes to a 16-bit (2-byte) value, but that decoded value
// carries NO integrity information — every 16-bit value is a structurally valid
// decoded key. The integrity lives entirely in the on-wire encoding: a 40-bit
// frame of ten 4-bit nibbles — a start nibble (0b0001), eight data nibbles each
// of which must be one of exactly four patterns (1110/1101/1011/0111, each
// carrying 2 bits), and a stop nibble (0b0001). So this decoder takes the
// *on-wire frame* (what a raw demod / logic-analyser capture produces): it
// validates the start/stop/data-nibble constraints — a strong gate — and
// extracts the 16-bit key. Decoding the rendered 2-byte ID would be a no-op with
// no verification, so it is deliberately not what this accepts.
//
// Input is the 40-bit on-wire frame as 10 hex nibbles (5 bytes), MSB-nibble
// first. The bit-period timing of the on-air signal is the reader's concern and
// out of scope.
//
// # Wrap-vs-native judgement
//
//	Native. The decode is a nibble walk + a 4-entry pattern map; stdlib only,
//	no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The frame structure (start/stop 0b0001, the four valid data-nibble patterns
//	and their 2-bit mapping E->11 / D->10 / B->01 / 7->00) is taken from the
//	Flipper Zero firmware (lib/ibutton/protocols/misc/protocol_cyfral.c). The
//	nibble constraints are a strong structural gate (~(4/16)^8 false-accept), so
//	a frame that fails any of them is rejected as not-a-Cyfral-frame rather than
//	mis-decoded. The mapping is hand-checkable, so no external vector is needed.
package cyfral

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is a decoded Cyfral iButton key.
type Result struct {
	Format string `json:"format"`
	Key    int    `json:"key"`
	KeyHex string `json:"key_hex"`
	RawHex string `json:"raw_hex"`

	Notes []string `json:"notes,omitempty"`
}

// nibbleBits maps each valid Cyfral data nibble to the 2 bits it carries.
var nibbleBits = map[byte]int{0xE: 0b11, 0xD: 0b10, 0xB: 0b01, 0x7: 0b00}

// Decode parses a 40-bit (10-nibble / 5-byte) on-wire Cyfral frame from hex
// (whitespace / ':' / '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) != 5 {
		return nil, fmt.Errorf("cyfral: need exactly 5 bytes (40-bit on-wire frame: start + 8 data + stop nibbles), got %d", len(b))
	}

	// Unpack the ten 4-bit nibbles, MSB-nibble first.
	nib := make([]byte, 10)
	for i := 0; i < 5; i++ {
		nib[i*2] = b[i] >> 4
		nib[i*2+1] = b[i] & 0x0F
	}

	if nib[0] != 0x1 {
		return nil, fmt.Errorf("cyfral: start nibble is 0x%X, expected 0x1 — not a Cyfral frame", nib[0])
	}
	if nib[9] != 0x1 {
		return nil, fmt.Errorf("cyfral: stop nibble is 0x%X, expected 0x1 — not a Cyfral frame", nib[9])
	}
	key := 0
	for i := 1; i <= 8; i++ {
		bits, ok := nibbleBits[nib[i]]
		if !ok {
			return nil, fmt.Errorf("cyfral: data nibble %d is 0x%X, not one of {0x7,0xB,0xD,0xE} — not a Cyfral frame", i, nib[i])
		}
		key = key<<2 | bits
	}

	r := &Result{
		Format: "Cyfral",
		Key:    key,
		KeyHex: fmt.Sprintf("%04X", key),
		RawHex: strings.ToUpper(hex.EncodeToString(b)),
	}
	r.Notes = append(r.Notes,
		"Cyfral iButton key — decoded from the on-wire frame (start/stop 0b0001 + 8 data nibbles, each one of 1110/1101/1011/0111 carrying 2 bits); the nibble constraints are the integrity gate",
		"the rendered 2-byte ID alone carries no integrity information, so this validates and decodes the on-wire frame form")
	return r, nil
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("cyfral: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("cyfral: input is not valid hex: %w", err)
	}
	return b, nil
}
