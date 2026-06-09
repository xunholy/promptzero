// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Hormann HSM (garage door / gate remotes)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware decoder;
// no third-party dependency, no shell-out. Decode-only (passive identification).
//
// Hormann is one of the most common European garage-door brands; the HSM
// fixed-code remote is OOK / PWM at 433.92 MHz.
//
// Modulation : OOK, Pulse Width Modulation
// Timing     : te_short 500 µs, te_long 1000 µs (= 2×te_short), te_delta 200 µs
// Header     : a 24×te_short (~12000 µs) guard mark + te_short space precedes
//              (and a repeat of it terminates) the frame.
// Payload    : 44-bit static code, MSB-first.
// Bit "1"    : te_long mark + te_short space
// Bit "0"    : te_short mark + te_long space
// Fixed gate : every valid HSM code has the bits of HORMANN_HSM_PATTERN
//              (0xFF000000003) set — the top 8 bits and bottom 2 bits — so a
//              frame failing (code & PATTERN) == PATTERN is rejected, not
//              mis-identified. button = (code >> 8) & 0xF.
// Frequency  : 433.92 MHz
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/hormann.c
//     (te_short=500, te_long=1000, te_delta=200, min_count_bit_for_found=44,
//     HORMANN_HSM_PATTERN=0xFF000000003; the feed() PWM state machine,
//     get_upload() encoder, and check() pattern gate / btn split). Hormann HSM
//     carries no rolling code or CRC, so a frame is gated by the header sync,
//     the 44-bit count, the per-bit PWM timing, and the fixed-pattern bits.

package protocols

import "fmt"

// hormannPattern is HORMANN_HSM_PATTERN: every valid HSM code has these bits set.
const hormannPattern = 0xFF000000003

// Hormann decodes Hormann HSM 44-bit fixed-code OOK/PWM frames.
type Hormann struct{}

func (p Hormann) Name() string     { return "Hormann HSM" }
func (p Hormann) BitRate() float64 { return 667.0 } // ~1 bit per (te_short+te_long)=1500 µs

// Decode attempts to decode a Hormann HSM frame from the pulse sequence.
//
// It syncs on the 24×te_short (~12000 µs) guard mark, then reads 44 MSB-first
// PWM bits where the mark length selects the bit (te_short → 0, te_long → 1).
// A frame whose decoded code does not carry the fixed HORMANN_HSM_PATTERN bits
// is rejected.
func (p Hormann) Decode(pulses []int) (Result, error) {
	const teShort, teLong, delta = 500, 1000, 250
	const syncMark = 24 * teShort // ~12000 µs guard

	// Sync on the long guard mark; the bits begin two entries later (after the
	// guard mark and its trailing te_short space).
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		if pulses[i] > 0 && abs32(pulses[i]-syncMark) <= 6*delta {
			start = i + 2
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("hormann: guard sync not found")
	}

	bits := make([]byte, 0, 44)
	matched := 0
	i := start
	for len(bits) < 44 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 || space >= 0 {
			break
		}
		switch {
		case abs32(mark-teShort) <= delta:
			bits = append(bits, 0)
			matched++
		case abs32(mark-teLong) <= delta:
			bits = append(bits, 1)
			matched++
		default:
			i = len(pulses) // unrecognised mark — stop
			continue
		}
		i += 2
	}
	if len(bits) < 44 {
		return Result{}, fmt.Errorf("hormann: only %d of 44 bits decoded", len(bits))
	}

	var data uint64
	for _, b := range bits {
		data = data<<1 | uint64(b)
	}
	if data&hormannPattern != hormannPattern {
		return Result{}, fmt.Errorf("hormann: fixed-pattern bits not set (not a Hormann HSM frame)")
	}
	button := (data >> 8) & 0xF

	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 44.0,
		Bits:       bits[:44],
		Payload: map[string]any{
			"code":   data,
			"button": button,
			"te_us":  teShort,
		},
	}, nil
}
