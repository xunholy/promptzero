// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "fmt"

// Philips RC5 nominal timings in microseconds. RC5 is Manchester (bi-phase)
// coded — fundamentally different from the pulse-distance (NEC / Samsung) and
// pulse-width (SIRC) protocols: there is no leader, and every bit is a
// half-bit-period transition. The bit period is 1778µs (two 889µs half-bits),
// modulated on a 36 kHz carrier. Per the Philips / IEEE-802.3 Manchester
// convention a logical 1 is an off→on transition in the middle of the bit
// (first half a 889µs space, second half a 889µs mark) and a logical 0 is the
// reverse (mark then space).
const (
	rc5HalfBit = 889
	rc5FullBit = 1778
)

// decodeRC5 decodes a 14-bit Philips RC5 / RC5X frame from its parsed timings.
// RC5 has no checksum, so correctness is gated structurally: every duration
// must classify cleanly as one (~889µs) or two (~1778µs) half-bits, the
// reconstructed stream must be exactly 28 half-bits forming 14 valid
// Manchester bit-pairs, and the first start bit (S1) must be 1 — a
// polarity-inverted or non-RC5 pulse train fails one of these and is rejected,
// not mis-decoded.
//
// The frame layout (MSB first) is: S1, S2, toggle, 5 address bits, 6 command
// bits. In RC5X (extended) S2 carries the inverted 7th command bit, extending
// the command range to 0-127; classic RC5 keeps S2 = 1 (command 0-63).
func decodeRC5(t []int) (*Result, error) {
	// Reconstruct the per-half-bit signal level. A capture starts at the
	// first mark (S1's second half), so the leading off half-bit of S1=1 is
	// never recorded — prepend it.
	half := make([]bool, 0, 32)
	half = append(half, false) // leading off (S1 first half)
	for i, d := range t {
		level := i%2 == 0 // even index = mark (on); odd = space (off)
		switch {
		case within(d, rc5HalfBit):
			half = append(half, level)
		case within(d, rc5FullBit):
			half = append(half, level, level)
		default:
			return nil, fmt.Errorf("ir: RC5 duration %dµs is neither ~889µs nor ~1778µs", d)
		}
	}
	// A frame ending in a 0 bit ends in an off half-bit that the capture may
	// drop as idle; pad to an even half-bit count.
	if len(half)%2 == 1 {
		half = append(half, false)
	}
	if len(half) != 28 {
		return nil, fmt.Errorf("ir: RC5 frame reconstructs to %d half-bits; expected 28 (14 bits)", len(half))
	}

	bits := make([]int, 14)
	for i := 0; i < 14; i++ {
		h0, h1 := half[i*2], half[i*2+1]
		switch {
		case !h0 && h1: // off,on -> 1
			bits[i] = 1
		case h0 && !h1: // on,off -> 0
			bits[i] = 0
		default:
			return nil, fmt.Errorf("ir: RC5 bit %d is not a valid Manchester transition", i)
		}
	}
	if bits[0] != 1 {
		return nil, fmt.Errorf("ir: RC5 start bit S1 is 0 (a non-RC5 or polarity-inverted capture)")
	}

	s2 := bits[1]
	toggle := bits[2]
	address := 0
	for i := 3; i < 8; i++ {
		address = address<<1 | bits[i]
	}
	command := 0
	for i := 8; i < 14; i++ {
		command = command<<1 | bits[i]
	}

	out := &Result{
		Protocol:      "RC5",
		Address:       address,
		Command:       command,
		Bits:          14,
		ChecksumValid: false,
		Notes: []string{
			fmt.Sprintf("toggle bit = %d (flips on each distinct key press; unchanged while a key is held)", toggle),
			"RC5 carries no checksum — gated structurally (14 valid Manchester bits, S1=1)",
		},
	}
	if s2 == 0 {
		// RC5X: S2 is the inverted MSB of a 7-bit command.
		out.Protocol = "RC5X"
		out.Command |= 0x40
		out.Notes = append(out.Notes, "RC5X extended frame: S2=0 sets command bit 6 (command range 64-127)")
	}
	out.AddressHex = fmt.Sprintf("0x%02X", out.Address)
	out.CommandHex = fmt.Sprintf("0x%02X", out.Command)
	return out, nil
}
