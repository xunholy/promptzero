// SPDX-License-Identifier: AGPL-3.0-or-later

// Test helpers shared by all protocol tests in this package.
package protocols_test

// encodePWMFrame synthesises a PWM pulse frame for testing.
// sync: syncHigh×te mark, syncLow×te space.
// "1" = oneHigh×te mark + oneLow×te space.
// "0" = zeroHigh×te mark + zeroLow×te space.
// repeat: number of full frame repetitions.
func encodePWMFrame(bits []byte, te, syncHigh, syncLow, oneHigh, oneLow, zeroHigh, zeroLow, repeat int) []int {
	if repeat < 1 {
		repeat = 1
	}
	var frame []int
	if syncHigh > 0 {
		frame = append(frame, syncHigh*te)
	}
	if syncLow > 0 {
		frame = append(frame, -(syncLow * te))
	}
	for _, b := range bits {
		if b != 0 {
			frame = append(frame, oneHigh*te, -(oneLow * te))
		} else {
			frame = append(frame, zeroHigh*te, -(zeroLow * te))
		}
	}
	out := make([]int, 0, len(frame)*repeat)
	for i := 0; i < repeat; i++ {
		out = append(out, frame...)
	}
	return out
}

// encodeSyncSpaceThenPDM synthesises a PDM frame preceded by a long space sync.
// "1" = 1×te mark + longSpace×te space; "0" = 1×te mark + shortSpace×te space.
func encodeSyncSpaceThenPDM(bits []byte, te, syncSpaceTE, oneSpaceTE, zeroSpaceTE int) []int {
	out := []int{-(syncSpaceTE * te)}
	for _, b := range bits {
		if b != 0 {
			out = append(out, te, -(oneSpaceTE * te))
		} else {
			out = append(out, te, -(zeroSpaceTE * te))
		}
	}
	return out
}

// uint16ToBits converts a uint16 to n MSB-first bits.
func uint16ToBits(v uint16, n int) []byte {
	bits := make([]byte, n)
	for i := 0; i < n; i++ {
		bits[i] = byte((v >> uint(n-1-i)) & 1)
	}
	return bits
}

// uint32ToBits converts a uint32 to n MSB-first bits.
func uint32ToBits(v uint32, n int) []byte {
	bits := make([]byte, n)
	for i := 0; i < n; i++ {
		bits[i] = byte((v >> uint(n-1-i)) & 1)
	}
	return bits
}

// encodeManchesterFrame synthesises a Manchester-encoded frame with a sync
// preamble (long mark + long space) followed by Manchester bits.
func encodeManchesterFrame(bits []byte, te, syncMarkTE, syncSpaceTE int) []int {
	out := []int{syncMarkTE * te, -(syncSpaceTE * te)}
	for _, b := range bits {
		if b != 0 {
			out = append(out, te, -te)
		} else {
			out = append(out, -te, te)
		}
	}
	return out
}
