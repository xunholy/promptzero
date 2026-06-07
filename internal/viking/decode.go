// SPDX-License-Identifier: AGPL-3.0-or-later

// Package viking decodes the Viking 125 kHz LF access-control data block — the
// credential format used by Viking / "Viking Acs" readers and fobs. It recovers
// the 32-bit card ID and validates the 8-bit checksum. It is the offline
// complement to the project's other LF-RFID decoders (em4100_decode,
// fdxb_decode, ioprox_decode, jablotron_decode) and the PACS/Wiegand decoder.
//
// Input is the *decoded* 64-bit (8-byte) Viking block — the bytes a demodulator
// such as Proxmark3's `lf viking demod` or a Flipper Zero LF read emits,
// MSB-first. The on-air ASK/Manchester demodulation is the reader's concern and
// out of scope here, so the decode is deterministic.
//
// # Bit layout of the 64-bit block
//
//	bits  0..23   preamble — 0xF2 0x00 0x00
//	bits 24..55   card ID (32 bits)
//	bits 56..63   checksum (8 bits)
//
// The checksum is defined so that the XOR of all eight bytes equals 0xA8 —
// equivalently checksum = cardByte3 XOR cardByte2 XOR cardByte1 XOR cardByte0
// XOR 0xF2 XOR 0xA8 (the 0x00 preamble bytes XOR to nothing).
//
// # Wrap-vs-native judgement
//
//	Native. The decode is fixed bit/byte extraction plus an XOR checksum;
//	stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The bit layout and the checksum are taken from — and agree byte-for-byte
//	between — TWO independent reference implementations: the Proxmark3 client
//	(cmdlfviking.c getVikingBits / isValidVikingChecksum) and the Flipper Zero
//	firmware (lib/lfrfid/protocols/protocol_viking.c). The 0xF20000 preamble is
//	a hard structural gate: a block without it is rejected as not-a-Viking-frame
//	rather than mis-decoded. The XOR checksum is the integrity gate (surfaced as
//	crc_valid); a block that parses structurally but fails the checksum is
//	reported as such, never asserted as a real credential.
package viking

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is a decoded Viking credential.
type Result struct {
	Format string `json:"format"`

	CardID    uint32 `json:"card_id"`
	CardIDHex string `json:"card_id_hex"`

	CRC         string `json:"crc"`
	CRCExpected string `json:"crc_expected"`
	CRCValid    bool   `json:"crc_valid"`

	RawHex string   `json:"raw_hex"`
	Notes  []string `json:"notes,omitempty"`
}

// Decode parses a 64-bit (8-byte) Viking block from hex (whitespace / ':' /
// '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("viking: need exactly 8 bytes (64-bit Viking block), got %d", len(b))
	}

	// Structural gate: the 24-bit preamble must be 0xF2 0x00 0x00.
	if b[0] != 0xF2 || b[1] != 0x00 || b[2] != 0x00 {
		return nil, fmt.Errorf("viking: preamble is %02X%02X%02X, expected F20000 — not a Viking frame", b[0], b[1], b[2])
	}

	cardID := binary.BigEndian.Uint32(b[3:7])
	crc := b[7]

	// The data checksum is the value at byte 7 that makes XOR(all 8 bytes) ==
	// 0xA8. Recompute it from the card bytes (the 0x00 preamble bytes XOR to 0).
	calc := b[3] ^ b[4] ^ b[5] ^ b[6] ^ 0xF2 ^ 0xA8

	r := &Result{
		Format:      "Viking",
		CardID:      cardID,
		CardIDHex:   fmt.Sprintf("%08X", cardID),
		CRC:         fmt.Sprintf("0x%02X", crc),
		CRCExpected: fmt.Sprintf("0x%02X", calc),
		CRCValid:    crc == calc,
		RawHex:      strings.ToUpper(hex.EncodeToString(b)),
	}
	if !r.CRCValid {
		r.Notes = append(r.Notes, fmt.Sprintf("checksum mismatch: frame carries 0x%02X but the data computes 0x%02X (XOR of all bytes != 0xA8) — structurally a Viking frame but the integrity check fails (corrupt read or not a genuine credential)", crc, calc))
	}
	r.Notes = append(r.Notes, "Viking 125 kHz LF access credential — 32-bit card ID + XOR checksum; layout/checksum per the Proxmark3 and Flipper Zero references")
	return r, nil
}

// Encode builds the 64-bit (8-byte) Viking block from a 32-bit card ID,
// returning it as an upper-case hex string. It is the inverse of Decode:
// Decode(Encode(id)).CardID == id with a valid checksum. The checksum is set so
// the XOR of all eight bytes equals 0xA8.
func Encode(cardID uint32) string {
	b := make([]byte, 8)
	b[0] = 0xF2 // preamble
	binary.BigEndian.PutUint32(b[3:7], cardID)
	b[7] = b[3] ^ b[4] ^ b[5] ^ b[6] ^ 0xF2 ^ 0xA8
	return strings.ToUpper(hex.EncodeToString(b))
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("viking: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("viking: input is not valid hex: %w", err)
	}
	return b, nil
}
