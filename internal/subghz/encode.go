// SPDX-License-Identifier: AGPL-3.0-or-later

package subghz

import (
	"fmt"
	"strings"
)

// EncodePWMPulses synthesises a raw pulse sequence for a PWM/OOK frame.
//
// Parameters:
//   - bits     : the payload bit sequence (1 or 0 per element)
//   - te       : timing element in microseconds (shortest pulse unit)
//   - syncHigh : sync mark duration in TE units (0 to omit sync)
//   - syncLow  : sync space duration in TE units (0 to omit sync)
//   - oneHigh  : mark duration for bit-1 in TE units
//   - oneLow   : space duration for bit-1 in TE units
//   - zeroHigh : mark duration for bit-0 in TE units
//   - zeroLow  : space duration for bit-0 in TE units
//   - repeat   : number of times to repeat the full frame (minimum 1)
func EncodePWMPulses(bits []byte, te, syncHigh, syncLow, oneHigh, oneLow, zeroHigh, zeroLow, repeat int) []int {
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

	pulses := make([]int, 0, len(frame)*repeat)
	for i := 0; i < repeat; i++ {
		pulses = append(pulses, frame...)
	}
	return pulses
}

// EncodeManchesterPulses synthesises a Manchester-encoded pulse sequence.
// Each bit occupies two half-symbol slots (each TE microseconds wide).
// IEEE 802.3 convention: 0 = low-to-high, 1 = high-to-low.
func EncodeManchesterPulses(bits []byte, te, repeat int) []int {
	if repeat < 1 {
		repeat = 1
	}
	var frame []int
	for _, b := range bits {
		if b != 0 {
			// 1 = mark then space (high → low)
			frame = append(frame, te, -te)
		} else {
			// 0 = space then mark (low → high)
			frame = append(frame, -te, te)
		}
	}
	pulses := make([]int, 0, len(frame)*repeat)
	for i := 0; i < repeat; i++ {
		pulses = append(pulses, frame...)
	}
	return pulses
}

// SubFileString serialises a pulse slice as a minimal Flipper .sub file
// (Protocol: RAW). The result can be written directly to a .sub file or
// base64-encoded for the subghz_classify tool.
func SubFileString(frequency uint64, preset string, pulses []int) string {
	var sb strings.Builder
	sb.WriteString("Filetype: Flipper SubGhz Key File\n")
	sb.WriteString("Version: 1\n")
	fmt.Fprintf(&sb, "Frequency: %d\n", frequency)
	fmt.Fprintf(&sb, "Preset: %s\n", preset)
	sb.WriteString("Protocol: RAW\n")

	// Write in chunks of 512 pulses per RAW_Data line (Flipper convention).
	const chunkSize = 512
	for i := 0; i < len(pulses); i += chunkSize {
		end := i + chunkSize
		if end > len(pulses) {
			end = len(pulses)
		}
		chunk := pulses[i:end]
		sb.WriteString("RAW_Data:")
		for _, p := range chunk {
			fmt.Fprintf(&sb, " %d", p)
		}
		sb.WriteByte('\n')
	}
	return sb.String()
}
