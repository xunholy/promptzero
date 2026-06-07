// SPDX-License-Identifier: AGPL-3.0-or-later

// Package noralsy decodes the Noralsy 125 kHz LF access-control data block — the
// credential format used by Noralsy readers/fobs, common in French (and wider
// European) residential access control and intercom systems. It recovers the
// card ID and the manufacture year and validates the two nibble checksums. It
// is the offline complement to the project's other LF-RFID decoders
// (em4100_decode, fdxb_decode, ioprox_decode, jablotron_decode, viking_decode)
// and the PACS/Wiegand decoder.
//
// Input is the *decoded* 96-bit (12-byte) Noralsy block — the bytes a
// demodulator such as Proxmark3's `lf noralsy demod` or a Flipper Zero LF read
// emits, MSB-first. The on-air ASK/Manchester demodulation is the reader's
// concern and out of scope here, so the decode is deterministic.
//
// # Bit layout of the 96-bit block (three 32-bit words)
//
//	bits  0..31   preamble word — 0xBB0214FF
//	bits 32..43   card ID, upper 12 bits
//	bits 44..51   year (8-bit BCD)
//	bits 52..55   (unknown / reserved)
//	bits 56..63   card ID, middle 8 bits
//	bits 64..71   card ID, lower 8 bits
//	bits 72..75   chk1 (4-bit nibble-XOR over bits 32..71)
//	bits 76..79   chk2 (4-bit nibble-XOR over bits 0..75)
//	bits 80..95   (trailer / unused — outside both checksums)
//
// The card ID is the 28-bit value (upper<<16 | middle<<8 | lower); Proxmark
// renders it BCD-decoded as a decimal, Flipper renders the packed value as hex
// — both are surfaced. Each nibble checksum is the XOR of successive 4-bit
// nibbles over its range, low nibble kept.
//
// # Wrap-vs-native judgement
//
//	Native. The decode is fixed bit extraction plus two nibble-XOR checksums;
//	stdlib only, no new go.mod dep.
//
// # Verifiable / no confidently-wrong output
//
//	The bit layout, the (non-contiguous) card-ID assembly masks, the year field
//	and the two nibble checksums are taken from — and agree byte-for-byte
//	between — TWO independent reference implementations: the Proxmark3 client
//	(cmdlfnoralsy.c noralsy_chksum + the cardid/year assembly) and the Flipper
//	Zero firmware (lib/lfrfid/protocols/protocol_noralsy.c). The 32-bit
//	0xBB0214FF preamble is a hard structural gate (a ~1-in-4-billion marker): a
//	block without it is rejected as not-a-Noralsy-frame rather than mis-decoded.
//	The two checksums are surfaced as chk1_valid / chk2_valid (a frame whose
//	checksums fail is reported as such, never asserted as a real credential).
//	The two references DISAGREE only on card-ID presentation (Proxmark BCD-
//	decimal vs Flipper hex), so BOTH are surfaced (with a not-BCD flag) rather
//	than asserting one; the 19xx/20xx century split is a documented heuristic
//	and noted as such.
package noralsy

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is a decoded Noralsy credential.
type Result struct {
	Format string `json:"format"`

	PreambleHex string `json:"preamble_hex"`

	CardIDHex    string `json:"card_id_hex"`           // packed 28-bit value as hex (Flipper view)
	CardIDPacked uint32 `json:"card_id_packed"`        // the packed value
	CardIDBCD    uint64 `json:"card_id_bcd,omitempty"` // BCD-decoded decimal (Proxmark view), when BCD-valid
	CardIDIsBCD  bool   `json:"card_id_is_bcd"`

	Year        int    `json:"year"`
	YearBCDByte string `json:"year_bcd_byte"`

	Chk1Valid bool `json:"chk1_valid"`
	Chk2Valid bool `json:"chk2_valid"`

	RawHex string   `json:"raw_hex"`
	Notes  []string `json:"notes,omitempty"`
}

const preamble = 0xBB0214FF

// Decode parses a 96-bit (12-byte) Noralsy block from hex (whitespace / ':' /
// '-' / '_' separators and a '0x' prefix tolerated).
func Decode(input string) (*Result, error) {
	b, err := normaliseHex(input)
	if err != nil {
		return nil, err
	}
	if len(b) != 12 {
		return nil, fmt.Errorf("noralsy: need exactly 12 bytes (96-bit Noralsy block), got %d", len(b))
	}

	word0 := binary.BigEndian.Uint32(b[0:4])
	if word0 != preamble {
		return nil, fmt.Errorf("noralsy: preamble word is 0x%08X, expected 0x%08X — not a Noralsy frame", word0, preamble)
	}

	raw2 := binary.BigEndian.Uint32(b[4:8])  // bits 32..63
	raw3 := binary.BigEndian.Uint32(b[8:12]) // bits 64..95

	// Card ID assembly (identical in both references).
	cardID := ((raw2 & 0xFFF00000) >> 20) << 16
	cardID |= (raw2 & 0xFF) << 8
	cardID |= (raw3 & 0xFF000000) >> 24

	// 8-bit BCD year at bits 44..51.
	yearBCD := byte((raw2 & 0x000FF000) >> 12)
	yearDec := bcd2dec(uint32(yearBCD))
	year := int(yearDec)
	if yearDec > 60 {
		year += 1900
	} else {
		year += 2000
	}

	cardIDDec, isBCD := bcd2decN(cardID, 7)

	r := &Result{
		Format:       "Noralsy",
		PreambleHex:  fmt.Sprintf("0x%08X", word0),
		CardIDHex:    fmt.Sprintf("%07X", cardID),
		CardIDPacked: cardID,
		CardIDIsBCD:  isBCD,
		Year:         year,
		YearBCDByte:  fmt.Sprintf("0x%02X", yearBCD),
		Chk1Valid:    nibbleXOR(b, 32, 40) == getBits4(b, 72),
		Chk2Valid:    nibbleXOR(b, 0, 76) == getBits4(b, 76),
		RawHex:       strings.ToUpper(hex.EncodeToString(b)),
	}
	if isBCD {
		r.CardIDBCD = cardIDDec
	} else {
		r.Notes = append(r.Notes, "card ID is not valid BCD (a nibble exceeds 9) — the Proxmark BCD-decimal render is omitted; use card_id_hex / card_id_packed")
	}
	if !r.Chk1Valid || !r.Chk2Valid {
		r.Notes = append(r.Notes, fmt.Sprintf("checksum mismatch (chk1_valid=%v chk2_valid=%v) — preamble matches Noralsy but the integrity nibbles fail (corrupt read or not a genuine credential)", r.Chk1Valid, r.Chk2Valid))
	}
	r.Notes = append(r.Notes,
		"card ID presentation differs between references: Proxmark renders it BCD-decoded (card_id_bcd), Flipper renders the packed value as hex (card_id_hex) — both surfaced",
		"the 19xx/20xx century split (year-BCD > 60 => 19xx) is a documented heuristic, not an on-tag field",
		"Noralsy 125 kHz LF access credential — card ID + year + two nibble checksums; layout/checksums per the Proxmark3 and Flipper Zero references")
	return r, nil
}

// nibbleXOR XORs successive 4-bit nibbles over [start, start+length) and returns
// the low nibble — the Noralsy checksum (noralsy_chksum in both references).
func nibbleXOR(b []byte, start, length int) byte {
	var sum byte
	for i := 0; i < length; i += 4 {
		sum ^= getBits4(b, start+i)
	}
	return sum & 0x0F
}

// getBits4 reads the 4 bits at bit position pos (MSB-first).
func getBits4(b []byte, pos int) byte {
	var v byte
	for i := 0; i < 4; i++ {
		bit := pos + i
		v = (v << 1) | ((b[bit/8] >> (7 - uint(bit%8))) & 1)
	}
	return v
}

// bcd2dec decodes a BCD value (each nibble a decimal digit), variable width.
func bcd2dec(v uint32) uint64 {
	d, _ := bcd2decN(v, nibbleCount(v))
	return d
}

// bcd2decN decodes the low n nibbles of v as BCD digits (MSB-first); ok is
// false if any nibble exceeds 9.
func bcd2decN(v uint32, n int) (dec uint64, ok bool) {
	ok = true
	for i := n - 1; i >= 0; i-- {
		nib := (v >> (uint(i) * 4)) & 0xF
		if nib > 9 {
			ok = false
		}
		dec = dec*10 + uint64(nib)
	}
	return dec, ok
}

func nibbleCount(v uint32) int {
	n := 1
	for v >= 16 {
		v >>= 4
		n++
	}
	return n
}

func normaliseHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "0x")
	s = strings.TrimPrefix(s, "0X")
	rep := strings.NewReplacer(" ", "", "\t", "", "\n", "", "\r", "", ":", "", "-", "", "_", "")
	s = rep.Replace(s)
	if s == "" {
		return nil, fmt.Errorf("noralsy: empty input")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("noralsy: input is not valid hex: %w", err)
	}
	return b, nil
}
