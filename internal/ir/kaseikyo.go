// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "fmt"

// Kaseikyo (a.k.a. Panasonic / Matsushita) nominal timings in microseconds.
// Pulse-distance, unit = 432µs: an 8-unit/4-unit header then 48 LSB-first bits
// (bit mark = 1 unit; 0-space = 1 unit, 1-space = 3 units). Kaseikyo is the
// shared frame format behind Panasonic, Denon, JVC, Sharp and Mitsubishi
// consumer IR. Timings + layout per Arduino-IRremote (ir_Kaseikyo.hpp), the SB-
// Projects Kaseikyo reference and the Flipper IR stack.
const (
	kaseikyoUnit        = 432
	kaseikyoHeaderMark  = 8 * kaseikyoUnit // 3456
	kaseikyoHeaderSpace = 4 * kaseikyoUnit // 1728
	kaseikyoBitMark     = kaseikyoUnit     // 432
	kaseikyoZeroSpace   = kaseikyoUnit     // 432
	kaseikyoOneSpace    = 3 * kaseikyoUnit // 1296
)

// decodeKaseikyo decodes a Kaseikyo frame from its parsed timings (the 3456µs
// header mark is at t[0], the 1728µs header space at t[1]).
//
// Frame layout (48 bits, LSB-first), as six bytes:
//
//	byte0..1  16-bit vendor (manufacturer) ID
//	byte2     low nibble: 4-bit vendor parity; high nibble: address bits 0-3
//	byte3     address bits 4-11
//	byte4     8-bit command
//	byte5     8-bit frame parity = byte2 ^ byte3 ^ byte4
//
// Two integrity gates verify the frame: the 4-bit vendor parity (XOR-fold of the
// vendor ID nibbles) and the 8-bit frame parity. Both must hold for a decode to
// be asserted; a frame that matches the header + 48-bit structure but fails a
// parity is reported as "Kaseikyo-like (parity failed)" with its raw bytes,
// never as a real frame. The per-vendor semantics of the 12-bit address / 8-bit
// command are vendor-specific; the generic frame fields are surfaced as-is.
func decodeKaseikyo(t []int) (*Result, error) {
	if !within(t[1], kaseikyoHeaderSpace) {
		return nil, fmt.Errorf("ir: Kaseikyo header space %dµs is not ~1728µs", t[1])
	}

	b, err := readKaseikyoBits(t)
	if err != nil {
		return nil, err
	}

	vendor := uint16(b[0]) | uint16(b[1])<<8
	vendorParity := b[2] & 0x0F
	vendorParityCalc := kaseikyoVendorParity(vendor)
	address := (int(b[3]) << 4) | int(b[2]>>4) // 12 bits
	command := int(b[4])
	frameParity := b[5]
	frameParityCalc := b[2] ^ b[3] ^ b[4]

	valid := vendorParity == vendorParityCalc && frameParity == frameParityCalc

	out := &Result{
		Protocol:      "Kaseikyo",
		Vendor:        int(vendor),
		VendorHex:     fmt.Sprintf("0x%04X", vendor),
		VendorName:    kaseikyoVendorName(vendor),
		Address:       address,
		AddressHex:    fmt.Sprintf("0x%03X", address),
		Command:       command,
		CommandHex:    fmt.Sprintf("0x%02X", command),
		Bits:          48,
		ChecksumValid: valid,
		RawBytesHex:   fmt.Sprintf("%02X%02X%02X%02X%02X%02X", b[0], b[1], b[2], b[3], b[4], b[5]),
	}
	if !valid {
		out.Protocol = "Kaseikyo-like (parity failed)"
		out.Notes = append(out.Notes, fmt.Sprintf("vendor parity %d (calc %d) / frame parity 0x%02X (calc 0x%02X) — header + 48-bit structure match Kaseikyo but an integrity gate fails; address/command shown unverified", vendorParity, vendorParityCalc, frameParity, frameParityCalc))
		return out, nil
	}
	out.Notes = append(out.Notes,
		"Kaseikyo (shared by Panasonic / Denon / JVC / Sharp / Mitsubishi) — gated by the 4-bit vendor parity AND the 8-bit frame parity",
		"the 12-bit address / 8-bit command are the generic frame fields; their per-vendor semantics vary, so they are surfaced as-is")
	return out, nil
}

// readKaseikyoBits reads the 48 LSB-first pulse-distance bits into six bytes.
func readKaseikyoBits(t []int) ([6]byte, error) {
	var b [6]byte
	bits := 0
	for i := 2; bits < 48; i += 2 {
		if i+1 >= len(t) {
			return b, fmt.Errorf("ir: Kaseikyo frame truncated at bit %d (need 48)", bits)
		}
		if !within(t[i], kaseikyoBitMark) {
			return b, fmt.Errorf("ir: Kaseikyo bit %d mark %dµs not ~432µs", bits, t[i])
		}
		switch {
		case within(t[i+1], kaseikyoOneSpace):
			b[bits/8] |= 1 << uint(bits%8) // LSB-first
		case within(t[i+1], kaseikyoZeroSpace):
			// zero bit — nothing to set
		default:
			return b, fmt.Errorf("ir: Kaseikyo bit %d space %dµs is neither ~432µs (0) nor ~1296µs (1)", bits, t[i+1])
		}
		bits++
	}
	return b, nil
}

// kaseikyoVendorParity folds the 16-bit vendor ID into its 4-bit parity
// (per Arduino-IRremote: p = v ^ (v>>8); p = (p ^ (p>>4)) & 0xF).
func kaseikyoVendorParity(v uint16) byte {
	p := v ^ (v >> 8)
	return byte((p ^ (p >> 4)) & 0x0F)
}

// kaseikyoVendorName maps the well-known Kaseikyo vendor IDs to a name; an
// unknown ID is reported by value (not guessed).
func kaseikyoVendorName(v uint16) string {
	switch v {
	case 0x2002:
		return "Panasonic / Matsushita"
	case 0x3254:
		return "Denon"
	case 0x0103:
		return "JVC"
	case 0x5AAA:
		return "Sharp"
	case 0xCB23:
		return "Mitsubishi"
	default:
		return "unknown vendor (not guessed)"
	}
}
