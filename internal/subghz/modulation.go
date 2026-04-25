// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import "math"

// DemodulateOOK decodes On-Off Keying (OOK) pulses to bits.
//
// OOK encodes a "1" as a long mark pulse and a "0" as a short mark pulse
// (or vice versa). The decoder classifies each mark (positive) pulse as
// 1 or 0 by comparing its duration to the median mark duration. Space
// (negative) pulses are used only as separators and are not decoded.
//
// The returned slice has one bit per mark pulse (1 or 0).
func DemodulateOOK(pulses []int) []byte {
	marks := make([]int, 0, len(pulses)/2)
	for _, p := range pulses {
		if p > 0 {
			marks = append(marks, p)
		}
	}
	if len(marks) == 0 {
		return nil
	}

	threshold := medianInt(marks)
	if threshold == 0 {
		return nil
	}

	bits := make([]byte, 0, len(marks))
	for _, m := range marks {
		if m >= threshold {
			bits = append(bits, 1)
		} else {
			bits = append(bits, 0)
		}
	}
	return bits
}

// DemodulatePWM decodes Pulse Width Modulation (PWM) encoded pulses to bits.
//
// PWM (also called Pulse Width Modulation) encodes bits via the duration of
// a mark pulse relative to TE (the base pulse unit). oneRatio specifies the
// multiplier above which a mark pulse is decoded as "1"; pulses below are "0".
//
// TE is estimated as the 25th-percentile mark duration (the smaller cluster
// centre), which is robust when "1" bits (long marks) outnumber "0" bits
// (short marks) in the captured payload.
//
// Common values: Princeton PT2262 uses oneRatio = 2.0 (marks ≥ 2×TE are "1",
// since "1" = 3×TE and "0" = 1×TE, with the midpoint at 2×TE).
// The returned slice has one bit per mark pulse.
func DemodulatePWM(pulses []int, oneRatio float64) []byte {
	marks := make([]int, 0, len(pulses)/2)
	for _, p := range pulses {
		if p > 0 {
			marks = append(marks, p)
		}
	}
	if len(marks) == 0 {
		return nil
	}

	// Use 25th-percentile as TE estimate to anchor the threshold to the
	// shorter (TE) pulse cluster regardless of bit distribution.
	base := percentileInt(marks, 25)
	if base == 0 {
		return nil
	}
	threshold := float64(base) * oneRatio

	bits := make([]byte, 0, len(marks))
	for _, m := range marks {
		if float64(m) >= threshold {
			bits = append(bits, 1)
		} else {
			bits = append(bits, 0)
		}
	}
	return bits
}

// DemodulateManchester decodes Manchester-encoded pulses to bits.
//
// Manchester encoding uses transitions mid-symbol:
//   - A low-to-high transition (short space then short mark) = 0 (IEEE 802.3)
//   - A high-to-low transition (short mark then short space) = 1 (IEEE 802.3)
//
// The decoder reconstructs the bit stream from alternating mark/space pairs.
// The median pulse duration serves as the half-symbol reference (TE).
// Pulses roughly equal to TE are half-symbols; pulses ≈ 2×TE are full symbols
// (no transition, so the previous bit repeats).
func DemodulateManchester(pulses []int) []byte {
	if len(pulses) < 2 {
		return nil
	}

	// Determine TE from absolute pulse durations.
	absPulses := make([]int, len(pulses))
	for i, p := range pulses {
		if p < 0 {
			absPulses[i] = -p
		} else {
			absPulses[i] = p
		}
	}
	te := medianInt(absPulses)
	if te == 0 {
		return nil
	}
	teHi := int(float64(te) * 1.6)

	bits := make([]byte, 0, len(pulses)/2)
	i := 0
	for i < len(pulses) {
		p := pulses[i]
		absP := p
		if absP < 0 {
			absP = -absP
		}

		if absP > teHi {
			// Double-length pulse: no mid-symbol transition.
			if len(bits) > 0 {
				bits = append(bits, bits[len(bits)-1])
			}
			i++
			continue
		}

		if i+1 >= len(pulses) {
			break
		}
		next := pulses[i+1]

		if p > 0 && next < 0 {
			bits = append(bits, 1) // High then Low → bit = 1
		} else if p < 0 && next > 0 {
			bits = append(bits, 0) // Low then High → bit = 0
		}
		i += 2
	}
	return bits
}

// BitsToBytes packs a bit slice (MSB first) into bytes, zero-padding the
// last byte if the slice length is not a multiple of 8.
func BitsToBytes(bits []byte) []byte {
	if len(bits) == 0 {
		return nil
	}
	nBytes := (len(bits) + 7) / 8
	out := make([]byte, nBytes)
	for i, b := range bits {
		if b != 0 {
			out[i/8] |= 1 << (7 - uint(i%8))
		}
	}
	return out
}

// BytesToBits unpacks bytes to a bit slice (MSB first), n bits total.
// If n > len(data)*8 the extra bits are zero.
func BytesToBits(data []byte, n int) []byte {
	bits := make([]byte, n)
	for i := 0; i < n; i++ {
		byteIdx := i / 8
		bitIdx := 7 - (i % 8)
		if byteIdx < len(data) {
			bits[i] = (data[byteIdx] >> uint(bitIdx)) & 1
		}
	}
	return bits
}

// medianInt returns the median of a non-empty int slice without sorting
// the original. Uses a copy for the partial sort.
func medianInt(vals []int) int {
	if len(vals) == 0 {
		return 0
	}
	cp := make([]int, len(vals))
	copy(cp, vals)
	sortInts(cp)
	return cp[len(cp)/2]
}

// percentileInt returns the value at the given percentile (0–100) of vals.
// Percentile 25 returns the 25th-percentile value (lower quartile).
func percentileInt(vals []int, pct int) int {
	if len(vals) == 0 {
		return 0
	}
	cp := make([]int, len(vals))
	copy(cp, vals)
	sortInts(cp)
	idx := (len(cp) * pct) / 100
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

// sortInts is an insertion sort for small int slices.
func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}

// abs32 returns the absolute value of v.
func abs32(v int) int {
	if v < 0 {
		return -v
	}
	return v
}

// nearRatio returns true when actual is within pct% of expected.
func nearRatio(actual, expected int, pct float64) bool {
	if expected == 0 {
		return actual == 0
	}
	ratio := math.Abs(float64(actual-expected)) / float64(expected)
	return ratio <= pct/100.0
}
