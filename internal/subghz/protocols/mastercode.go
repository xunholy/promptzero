// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Mastercode (gate / barrier remotes)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware decoder;
// no third-party dependency, no shell-out. Decode-only (passive identification).
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : te_short 1072 µs, te_long 2145 µs (≈2×TE)
// Payload    : 36-bit static code, MSB-first. serial = (code>>4) & 0xFFFF
//              (the eight tri-state DIP positions), button = (code>>2) & 0x03.
// Bit "0"    : te_short mark + te_long space
// Bit "1"    : te_long mark + te_short space
// Framing    : a ~15×te_short inter-frame gap both precedes the first bit and
//              terminates the frame (the last bit's space is the gap).
// Frequency  : 433.92 MHz
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/mastercode.c
//     (te_short=1072, te_long=2145, te_delta=150, min_count_bit=36; the feed()
//     state machine, get_upload() encoder, and check_remote_controller()
//     serial/btn split). Mastercode carries no checksum, so a frame is gated
//     only by the inter-frame sync gap, the 36-bit count and the per-bit PWM
//     timing; the classifier's confidence ranks it against other matches.

package protocols

import "fmt"

// Mastercode decodes Mastercode 36-bit fixed-code OOK/PWM frames.
type Mastercode struct{}

func (p Mastercode) Name() string     { return "Mastercode" }
func (p Mastercode) BitRate() float64 { return 311.0 } // ~1 bit per 3×te_short

// Decode attempts to decode a Mastercode frame from the pulse sequence.
//
// It anchors on the ~15×te_short inter-frame gap, then reads 36 MSB-first PWM
// bits where the mark length selects the bit (te_short → 0, te_long → 1; the
// space is the complement, except the final bit whose space is the gap).
func (p Mastercode) Decode(pulses []int) (Result, error) {
	// te_short ≈ 1072 µs; te_long (≈2×TE) also appears per bit, so the smallest
	// recurring bucket is the right TE estimate (the inter-frame gap is excluded
	// by the upper bound).
	te, ok := estimateTEMin(pulses, 600, 2600)
	if !ok {
		return Result{}, fmt.Errorf("mastercode: cannot estimate TE")
	}
	teLong := 2 * te

	// Sync on the inter-frame gap: a space of ~15×te_short.
	start := -1
	for i := 0; i < len(pulses); i++ {
		if pulses[i] < 0 && nearRatio(abs32(pulses[i]), 15*te, 40) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("mastercode: sync gap not found")
	}

	// Read 36 bits, classifying each by its mark length.
	bits := make([]byte, 0, 36)
	matched := 0
	i := start
	for len(bits) < 36 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 || space >= 0 {
			break
		}
		switch {
		case nearRatio(mark, te, 45):
			bits = append(bits, 0)
			matched++
		case nearRatio(mark, teLong, 45):
			bits = append(bits, 1)
			matched++
		default:
			i = len(pulses) // unrecognised mark — stop
			continue
		}
		i += 2
	}
	if len(bits) < 36 {
		return Result{}, fmt.Errorf("mastercode: only %d bits decoded", len(bits))
	}

	// 36 bits exceed uint32, so accumulate the code as uint64 (MSB-first).
	var data uint64
	for _, b := range bits {
		data = data<<1 | uint64(b)
	}
	serial := (data >> 4) & 0xFFFF
	button := (data >> 2) & 0x03

	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 36.0,
		Bits:       bits[:36],
		Payload: map[string]any{
			"code":   data,
			"serial": serial,
			"button": button,
			"te_us":  te,
		},
	}, nil
}
