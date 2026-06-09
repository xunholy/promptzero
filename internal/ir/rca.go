// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "fmt"

// RCA (the protocol used by RCA-brand TVs/AV gear) nominal timings in
// microseconds. RCA is pulse-distance — like NEC — but with its own distinct
// 4000µs/4000µs AGC leader and a 500µs bit mark followed by a 1000µs (0) or
// 2000µs (1) space. The frame is 24 bits, transmitted LSB-first per field:
// 4-bit address, 8-bit command, 4-bit address-inverse, 8-bit command-inverse.
// The two inverse fields are the checksum.
const (
	rcaPreambleMark  = 4000
	rcaPreambleSpace = 4000
	rcaBitMark       = 500
	rcaZeroSpace     = 1000
	rcaOneSpace      = 2000
)

// decodeRCA decodes an RCA frame from its parsed timings (the 4000µs leader
// mark at t[0], 4000µs space at t[1]). The 4-bit address and 8-bit command are
// each followed by their bitwise inverse; an RCA frame is reported as
// checksum-valid only when BOTH inversions hold — otherwise the raw fields are
// surfaced with a note rather than asserted, and a non-RCA pulse train fails
// the leader gate or a bit match and is rejected, not mis-decoded.
func decodeRCA(t []int) (*Result, error) {
	var data uint32
	bits := 0
	for i := 2; bits < 24; i += 2 {
		if i+1 >= len(t) {
			return nil, fmt.Errorf("ir: RCA frame truncated at bit %d (need 24)", bits)
		}
		if !within(t[i], rcaBitMark) {
			return nil, fmt.Errorf("ir: RCA bit %d mark %dµs not ~500µs", bits, t[i])
		}
		switch {
		case within(t[i+1], rcaOneSpace):
			data |= 1 << uint(bits) // LSB-first
		case within(t[i+1], rcaZeroSpace):
			// zero bit — nothing to set
		default:
			return nil, fmt.Errorf("ir: RCA bit %d space %dµs is neither ~1000µs (0) nor ~2000µs (1)", bits, t[i+1])
		}
		bits++
	}

	address := int(data & 0xF)
	command := int((data >> 4) & 0xFF)
	addrInv := int((data >> 12) & 0xF)
	cmdInv := int((data >> 16) & 0xFF)
	addrOK := address == (^addrInv & 0xF)
	cmdOK := command == (^cmdInv & 0xFF)

	out := &Result{
		Protocol:    "RCA",
		Bits:        24,
		Address:     address,
		Command:     command,
		RawBytesHex: fmt.Sprintf("%06X", data&0xFFFFFF),
	}
	if addrOK && cmdOK {
		out.ChecksumValid = true
		out.Notes = []string{"RCA — 4-bit address + 8-bit command, both inverse-field checksums validate"}
	} else {
		out.Notes = []string{"RCA-like: an inverse-field checksum failed (address inv ok=" +
			boolStr(addrOK) + ", command inv ok=" + boolStr(cmdOK) + ") — a misread frame or a non-RCA pulse-distance protocol; address/command shown unverified"}
	}
	out.AddressHex = fmt.Sprintf("0x%02X", address)
	out.CommandHex = fmt.Sprintf("0x%02X", command)
	return out, nil
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// encodeRCA builds an RCA timing list (the inverse of decodeRCA) from a 4-bit
// address + 8-bit command, emitting both inverse fields. Generation only — no
// IR TX.
func encodeRCA(address, command int) []int {
	// Pack the 24 bits LSB-first: address(4) | command(8) | ~address(4) |
	// ~command(8).
	data := uint32(address&0xF) |
		uint32(command&0xFF)<<4 |
		uint32((^address)&0xF)<<12 |
		uint32((^command)&0xFF)<<16

	t := []int{rcaPreambleMark, rcaPreambleSpace}
	for bit := 0; bit < 24; bit++ {
		t = append(t, rcaBitMark)
		if data&(1<<uint(bit)) != 0 {
			t = append(t, rcaOneSpace)
		} else {
			t = append(t, rcaZeroSpace)
		}
	}
	return append(t, rcaBitMark) // trailing stop mark
}
