// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fdxb decodes the ISO 11784/11785 FDX-B data block — the 134.2 kHz
// LF transponder format used by animal / pet microchips (and many "biothermo"
// and asset transponders). It recovers the country code, the 38-bit national
// identification number, the application flags, and validates the CRC-16.
//
// Input is the *de-stuffed* FDX-B data block (the bytes a demodulator such as
// Proxmark3's `lf fdxb` emits as the raw ID block) — MSB-first within each
// byte. The on-air framing (the 11-bit preamble and the control '1' inserted
// after every 8 data bits) is the demodulator's concern and is deliberately
// out of scope here: this package decodes the data block, not the raw RF
// bitstream, so its output is deterministic and independently verifiable.
//
// Layout of the 104-bit data block (all multi-bit fields are LSB-first, the
// FDX-B convention):
//
//	bits   0..37   national code (38 bits)
//	bits  38..47   country code (10 bits)
//	bit   48       data-block-status flag (1 => 24-bit extended block present)
//	bit   49       animal-application flag
//	bits  50..63   reserved
//	bits  64..79   CRC-16 (over the first 8 bytes / 64 bits)
//	bits  80..103  extended data block (24 bits)
//
// Wrap-vs-native: native. The decode is fixed bit/byte extraction plus a
// CRC-16; no third-party dependency is warranted. The field layout, the
// LSB-first bit order, and the CRC-16 parameters (CCITT polynomial 0x1021,
// init 0x0000, refin=false, refout=true, over the first 8 bytes) are taken
// from the Proxmark3 reference (common/crc16.c crc16_fdxb + client
// cmdlffdxb.c) and were verified byte-for-byte against two real decoded tags:
// country 528 / national 140000795552 (raw ID 05 D9 4D 19 04 21 00 01) and
// country 999 / national 1500030037 (CRC 0x8A1C) — not recalled.
//
// No confidently-wrong output: the CRC-16 is the integrity gate (the national
// and country codes are double-anchored and the computed CRC reproduces a
// published vector). The animal flag (bit 49, per the priority1design FDX-B
// reference) is surfaced as a secondary field and the reserved / extended bits
// are surfaced raw — a frame whose CRC fails is reported as such, never
// asserted as a real tag.
//
// Deferred: a full ISO-3166 country-code → name table (the numeric code is
// surfaced, with a note when it falls in the 900-999 manufacturer/test range);
// the semantics of the 24-bit extended data block (vendor-specific).
package fdxb

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// FDXB is a decoded FDX-B data block.
type FDXB struct {
	NationalCode      uint64   `json:"national_code"`
	CountryCode       int      `json:"country_code"`
	CountryNote       string   `json:"country_note,omitempty"`
	AnimalApplication bool     `json:"animal_application"`
	DataBlockPresent  bool     `json:"data_block_present"`
	IDBlockHex        string   `json:"id_block_hex"`
	CRCComputed       string   `json:"crc16_computed"`
	CRCStored         string   `json:"crc16_stored,omitempty"`
	CRCValid          *bool    `json:"crc16_valid,omitempty"`
	ExtendedHex       string   `json:"extended_data_hex,omitempty"`
	Notes             []string `json:"notes,omitempty"`
}

// DecodeHex decodes a hex-encoded FDX-B data block. ':' / '-' / '_' /
// whitespace separators are ignored.
func DecodeHex(s string) (*FDXB, error) {
	clean := strings.NewReplacer(":", "", "-", "", "_", "", " ", "", "\n", "", "\t", "").Replace(s)
	if clean == "" {
		return nil, fmt.Errorf("fdxb: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("fdxb: invalid hex: %w", err)
	}
	return Decode(b)
}

// Decode decodes an FDX-B data block: at least the 8-byte ID block; 10 bytes
// to additionally validate the CRC-16; 13 bytes to additionally surface the
// extended data block.
func Decode(b []byte) (*FDXB, error) {
	if len(b) < 8 {
		return nil, fmt.Errorf("fdxb: need at least the 8-byte ID block, got %d bytes", len(b))
	}
	bits := toBitsMSBF(b)

	out := &FDXB{
		NationalCode: readLSBF(bits, 32, 6)<<32 | readLSBF(bits, 0, 32),
		CountryCode:  int(readLSBF(bits, 38, 10)),
		IDBlockHex:   strings.ToUpper(hex.EncodeToString(b[:8])),
	}
	out.DataBlockPresent = bits[48] == 1
	out.AnimalApplication = bits[49] == 1
	out.CountryNote = countryNote(out.CountryCode)

	computed := crc16FDXB(b[:8])
	out.CRCComputed = fmt.Sprintf("0x%04X", computed)

	if len(b) >= 10 {
		stored := uint16(readLSBF(bits, 64, 16))
		out.CRCStored = fmt.Sprintf("0x%04X", stored)
		valid := stored == computed
		out.CRCValid = &valid
		if !valid {
			out.Notes = append(out.Notes, "CRC-16 mismatch — frame may be misframed or corrupt; treat the decode as unverified")
		}
	} else {
		out.Notes = append(out.Notes, "no CRC bytes supplied (need >=10 bytes); integrity unverified")
	}

	if len(b) >= 13 {
		out.ExtendedHex = strings.ToUpper(hex.EncodeToString(b[10:13]))
	}
	return out, nil
}

// toBitsMSBF expands bytes to a bit slice, most-significant bit first within
// each byte (the order in which Proxmark3 renders the FDX-B data block).
func toBitsMSBF(b []byte) []int {
	out := make([]int, len(b)*8)
	for i, x := range b {
		for j := 0; j < 8; j++ {
			out[i*8+j] = int((x >> uint(7-j)) & 1)
		}
	}
	return out
}

// readLSBF reads n bits starting at off, least-significant bit first (the bit
// at off is value bit 0).
func readLSBF(bits []int, off, n int) uint64 {
	var v uint64
	for i := 0; i < n && off+i < len(bits); i++ {
		v |= uint64(bits[off+i]) << uint(i)
	}
	return v
}

// crc16FDXB computes the FDX-B CRC-16: CCITT polynomial 0x1021, init 0x0000,
// no input reflection, output reflected, no final XOR (Proxmark3 crc16_fdxb).
func crc16FDXB(d []byte) uint16 {
	var crc uint16
	for _, b := range d {
		crc ^= uint16(b) << 8
		for i := 0; i < 8; i++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return reflect16(crc)
}

func reflect16(x uint16) uint16 {
	var r uint16
	for i := 0; i < 16; i++ {
		if x&(1<<uint(i)) != 0 {
			r |= 1 << uint(15-i)
		}
	}
	return r
}

// countryNote flags FDX-B country-code ranges that are not ISO-3166 countries
// (the manufacturer / test ranges), without asserting a country name.
func countryNote(code int) string {
	switch {
	case code == 999:
		return "test / unregistered range"
	case code >= 900 && code <= 998:
		return "manufacturer / shared-allocation range (not an ISO-3166 country)"
	default:
		return ""
	}
}
