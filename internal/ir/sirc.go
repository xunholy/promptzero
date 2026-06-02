// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "fmt"

// Sony SIRC nominal timings in microseconds. SIRC is pulse-width coded: a
// 2400µs leader mark + 600µs space, then each bit is a variable mark (1200µs
// = 1, 600µs = 0) followed by a fixed 600µs space. Data is LSB-first: 7
// command bits, then the address (5 bits for 12-bit SIRC, 8 for 15-bit, 5 +
// an 8-bit extension for 20-bit).
const (
	sircLeaderMark  = 2400
	sircLeaderSpace = 600
	sircOneMark     = 1200
	sircZeroMark    = 600
	sircBitSpace    = 600
)

// decodeSIRC decodes a Sony SIRC frame from its parsed timings (the 2400µs
// leader mark is at t[0]). SIRC has no checksum, so correctness is gated
// structurally: the leader must match, every bit's mark must classify cleanly
// as 1200µs (1) or 600µs (0) with a ~600µs space, and the total bit count
// must be exactly 12, 15, or 20 — anything else is rejected, not guessed.
func decodeSIRC(t []int) (*Result, error) {
	if !within(t[1], sircLeaderSpace) {
		return nil, fmt.Errorf("ir: Sony SIRC leader space %dµs is not ~600µs", t[1])
	}

	bits := make([]int, 0, 20)
	for i := 2; i < len(t); i += 2 {
		var bit int
		switch {
		case within(t[i], sircOneMark):
			bit = 1
		case within(t[i], sircZeroMark):
			bit = 0
		default:
			return nil, fmt.Errorf("ir: SIRC bit %d mark %dµs is neither ~1200µs (1) nor ~600µs (0)", len(bits), t[i])
		}
		// The inter-bit space is fixed; it may be absent on the final bit.
		if i+1 < len(t) && !within(t[i+1], sircBitSpace) {
			return nil, fmt.Errorf("ir: SIRC bit %d space %dµs is not ~600µs", len(bits), t[i+1])
		}
		bits = append(bits, bit)
	}

	var cmdBits, addrBits, extBits int
	var variant string
	switch len(bits) {
	case 12:
		cmdBits, addrBits, extBits, variant = 7, 5, 0, "12-bit"
	case 15:
		cmdBits, addrBits, extBits, variant = 7, 8, 0, "15-bit"
	case 20:
		cmdBits, addrBits, extBits, variant = 7, 5, 8, "20-bit"
	default:
		return nil, fmt.Errorf("ir: Sony SIRC frame has %d bits; expected exactly 12, 15, or 20", len(bits))
	}

	command := lsbValue(bits[:cmdBits])
	address := lsbValue(bits[cmdBits : cmdBits+addrBits])
	out := &Result{
		Protocol:   "Sony SIRC (" + variant + ")",
		Address:    address,
		AddressHex: fmt.Sprintf("0x%X", address),
		Command:    command,
		CommandHex: fmt.Sprintf("0x%02X", command),
		Bits:       len(bits),
		Notes: []string{
			"Sony SIRC carries no checksum; decode gated on the 2400µs leader, exact " + variant + " bit count, and per-bit timing",
		},
	}
	if extBits > 0 {
		ext := lsbValue(bits[cmdBits+addrBits:])
		out.Notes = append(out.Notes, fmt.Sprintf("20-bit extended byte 0x%02X", ext))
	}
	return out, nil
}

// lsbValue assembles bits in LSB-first transmission order into an integer
// (bits[0] is the least-significant bit).
func lsbValue(bits []int) int {
	v := 0
	for i, b := range bits {
		v |= b << uint(i)
	}
	return v
}
