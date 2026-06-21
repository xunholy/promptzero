// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"fmt"
)

// TSI is a decoded EMV Transaction Status Information (tag 9B): the 2-byte
// bitfield in which the terminal records which functions it actually performed
// during a transaction. It is the third member of the EMV transaction-outcome
// trio — the AIP (tag 82) says what the card can do, the TVR (tag 95) records
// what the terminal flagged, and the TSI records what the terminal carried out.
// The bit meanings are defined in EMV 4.3 Book 3, Annex C6; both bytes are
// terminal-defined and stable across payment systems.
type TSI struct {
	Raw   string   `json:"raw"`   // the 2 bytes, hex
	Bytes []string `json:"bytes"` // each byte, 0xNN

	// FunctionsPerformed lists the set bits — each a function the terminal
	// performed — in bit order (byte 1, high to low).
	FunctionsPerformed []string `json:"functions_performed"`

	// NonePerformed reports an all-zero TSI: the terminal recorded no
	// completed function (e.g. a transaction aborted very early).
	NonePerformed bool `json:"none_performed"`

	Notes []string `json:"notes,omitempty"`
}

// tsiBits maps each byte-1 mask to its EMV Book 3 Annex C6 meaning, in bit
// order (high to low). Byte 1 bits 2 and 1, and the whole of byte 2, are RFU.
var tsiBits = []struct {
	mask byte
	name string
}{
	{0x80, "Offline data authentication was performed"},
	{0x40, "Cardholder verification was performed"},
	{0x20, "Card risk management was performed"},
	{0x10, "Issuer authentication was performed"},
	{0x08, "Terminal risk management was performed"},
	{0x04, "Script processing was performed"},
}

// tsiByte1Defined is the OR of every named byte-1 bit; the complement is the
// byte-1 RFU mask.
const tsiByte1Defined = 0x80 | 0x40 | 0x20 | 0x10 | 0x08 | 0x04

// DecodeTSI decodes the raw bytes of EMV tag 9B (Transaction Status
// Information). The TSI is a fixed 2-byte bitfield, so it is gated
// structurally: exactly 2 bytes must be present. Byte 1's six defined bits are
// decoded per EMV Book 3 Annex C6; byte 1 bits 2/1 and the whole of byte 2 are
// RFU and are surfaced via a note rather than named (no confidently-wrong
// output).
func DecodeTSI(raw []byte) (*TSI, error) {
	if len(raw) != 2 {
		return nil, fmt.Errorf("emv: TSI (tag 9B) must be exactly 2 bytes, got %d", len(raw))
	}
	b1, b2 := raw[0], raw[1]
	out := &TSI{
		Raw:                fmt.Sprintf("%02X%02X", b1, b2),
		Bytes:              []string{fmt.Sprintf("0x%02X", b1), fmt.Sprintf("0x%02X", b2)},
		FunctionsPerformed: []string{},
	}
	for _, b := range tsiBits {
		if b1&b.mask != 0 {
			out.FunctionsPerformed = append(out.FunctionsPerformed, b.name)
		}
	}
	out.NonePerformed = len(out.FunctionsPerformed) == 0

	if rfu := b1 &^ byte(tsiByte1Defined); rfu != 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"byte 1 has RFU bit(s) set (0x%02X) — reserved for future use in EMV Book 3, surfaced raw", rfu))
	}
	if b2 != 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"byte 2 (0x%02X) is RFU in EMV Book 3 — surfaced raw, not interpreted", b2))
	}
	return out, nil
}

// DecodeTSIHex is the hex-string convenience wrapper.
func DecodeTSIHex(s string) (*TSI, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeTSI(b)
}
