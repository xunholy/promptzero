// SPDX-License-Identifier: AGPL-3.0-or-later

// Package protocols implements pure-Go decoders for the top-20 Sub-GHz
// remote control protocols captured by the Flipper Zero. Each decoder
// implements the subghz.Protocol interface (Name, BitRate, Decode).
//
// See the parent package (github.com/xunholy/promptzero/internal/subghz)
// for the Classifier, SubFile parser, and modulation primitives.
package protocols

import "math"

// Result mirrors subghz.Result — defined here to avoid a circular import.
// The parent package re-exports its own Result via classify.go.
type Result struct {
	Protocol   string
	Confidence float64
	Bits       []byte
	Payload    map[string]any
}

// -----------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------

// estimateTE estimates the timing element (TE) from a pulse sequence.
// TE is the most-common pulse unit within [minUS, maxUS].
// Pulses are bucketed to the nearest 50 µs to merge near-identical durations.
// Returns (te, true) on success or (0, false) when no plausible TE is found.
func estimateTE(pulses []int, minUS, maxUS int) (int, bool) {
	counts := make(map[int]int)
	for _, p := range pulses {
		a := p
		if a < 0 {
			a = -a
		}
		if a >= minUS && a <= maxUS {
			bucket := ((a + 25) / 50) * 50
			counts[bucket]++
		}
	}
	if len(counts) == 0 {
		return 0, false
	}
	best := 0
	bestN := 0
	for bucket, n := range counts {
		if n > bestN {
			bestN = n
			best = bucket
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

// estimateTEMin estimates TE as the smallest-value bucket that appears at least
// twice within [minUS, maxUS]. This is better for protocols where the short
// (TE) pulse appears less often than the long (2×TE or 3×TE) pulse in a given
// payload (e.g. Smartgate with many "1" bits).
func estimateTEMin(pulses []int, minUS, maxUS int) (int, bool) {
	counts := make(map[int]int)
	for _, p := range pulses {
		a := p
		if a < 0 {
			a = -a
		}
		if a >= minUS && a <= maxUS {
			bucket := ((a + 25) / 50) * 50
			counts[bucket]++
		}
	}
	// Find smallest bucket with count ≥ 2.
	best := 0
	for bucket, n := range counts {
		if n < 2 {
			continue
		}
		if best == 0 || bucket < best {
			best = bucket
		}
	}
	if best == 0 {
		return 0, false
	}
	return best, true
}

// nearRatio returns true when actual is within pct% of expected.
func nearRatio(actual, expected int, pct float64) bool {
	if expected == 0 {
		return actual == 0
	}
	ratio := math.Abs(float64(actual-expected)) / float64(expected)
	return ratio <= pct/100.0
}

// abs32 returns the absolute value of v.
func abs32(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// decodePWMBits decodes up to n PWM bits from pulses starting at pulses[0].
// "1" = 3×TE mark + 1×TE space; "0" = 1×TE mark + 3×TE space.
// Returns the decoded bits and a confidence score (0.0–1.0).
func decodePWMBits(pulses []int, te, n int) ([]byte, float64) {
	return decodePWMBitsRelaxed(pulses, te, n, 60)
}

// decodePWMBitsRelaxed is decodePWMBits with a configurable tolerance %.
func decodePWMBitsRelaxed(pulses []int, te, n int, pct float64) ([]byte, float64) {
	bits := make([]byte, 0, n)
	i := 0
	matched := 0
	for len(bits) < n && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		sp := abs32(space)
		if nearRatio(mark, 3*te, pct) && nearRatio(sp, te, pct) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(mark, te, pct) && nearRatio(sp, 3*te, pct) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}
	if n == 0 || len(bits) == 0 {
		return bits, 0
	}
	return bits, float64(matched) / float64(n)
}

// bitsToUint converts up to 32 bits (MSB first) to a uint32.
func bitsToUint(bits []byte) uint32 {
	var v uint32
	for _, b := range bits {
		v = (v << 1) | uint32(b&1)
	}
	return v
}

// bitsToUint32 converts exactly up to 32 bits (MSB first) to a uint32.
func bitsToUint32(bits []byte) uint32 {
	return bitsToUint(bits)
}

// bitsToUint32LSBFirst converts 32 bits transmitted LSB-first to a uint32
// with the natural bit order.
func bitsToUint32LSBFirst(bits []byte) uint32 {
	if len(bits) > 32 {
		bits = bits[:32]
	}
	var v uint32
	for i, b := range bits {
		if b != 0 {
			v |= 1 << uint(i)
		}
	}
	return v
}
