// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Marantec24 (garage-door / gate remotes, 24-bit variant)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware decoder;
// no third-party dependency, no shell-out. Decode-only (passive identification).
//
// Marantec24 is the 24-bit Marantec remote variant (distinct from the in-tree
// 12-bit Marantec): OOK / PWM at 433.92 / 868.35 MHz, common on European garage
// doors.
//
// Modulation : OOK, Pulse Width Modulation
// Timing     : te_short 800 µs, te_long 1600 µs (= 2×te_short), te_delta 200 µs
// Sync       : a 9×te_long (~14400 µs) inter-frame GAP (space) precedes (and
//              terminates) the frame; the final bit's space is that gap.
// Payload    : 24-bit code, MSB-first:
//                serial = code >> 4   (20-bit remote serial)
//                button = code & 0xF  (4-bit)
// Bit "0"    : te_long  mark (1600 µs) + 3×te_short space (2400 µs)
// Bit "1"    : te_short mark (800 µs)  + 2×te_long  space (3200 µs)
//              (the mark length alone selects the bit: long → 0, short → 1)
// Frequency  : 433.92 / 868.35 MHz
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/marantec24.c
//     (te_short=800, te_long=1600, te_delta=200, min_count_bit_for_found=24;
//     the feed() state machine — gap-sync + per-bit mark/space classification,
//     the last bit closed by the next gap — and check_remote_controller():
//     serial = data >> 4, btn = data & 0xF). Marantec24 carries no checksum, so
//     a frame is gated by the gap sync, the 24-bit count and the per-bit PWM
//     timing; the classifier ranks it against other matches by confidence.

package protocols

import "fmt"

// Marantec24 decodes Marantec 24-bit fixed-code OOK/PWM garage frames.
type Marantec24 struct{}

func (p Marantec24) Name() string     { return "Marantec24" }
func (p Marantec24) BitRate() float64 { return 250.0 } // ~1 bit per (mark+space)≈4000 µs

// Decode attempts to decode a Marantec24 frame from the pulse sequence. It syncs
// on the 9×te_long (~14400 µs) inter-frame gap, then reads 24 MSB-first bits
// where the mark length selects the bit (te_long → 0, te_short → 1).
func (p Marantec24) Decode(pulses []int) (Result, error) {
	const teShort, teLong, delta = 800, 1600, 300
	const gap = 9 * teLong // ~14400 µs inter-frame gap

	// Sync on the inter-frame gap (a long space); the first bit's mark follows.
	start := -1
	for i := 0; i < len(pulses); i++ {
		if pulses[i] < 0 && abs32(abs32(pulses[i])-gap) <= 4*teShort {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("marantec24: inter-frame gap sync not found")
	}

	bits := make([]byte, 0, 24)
	matched := 0
	i := start
	for len(bits) < 24 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 || space >= 0 {
			break
		}
		switch {
		case abs32(mark-teShort) <= delta:
			bits = append(bits, 1)
			matched++
		case abs32(mark-teLong) <= delta:
			bits = append(bits, 0)
			matched++
		default:
			i = len(pulses)
			continue
		}
		i += 2
	}
	if len(bits) < 24 {
		return Result{}, fmt.Errorf("marantec24: only %d of 24 bits decoded", len(bits))
	}

	var data uint64
	for _, b := range bits {
		data = data<<1 | uint64(b)
	}
	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 24.0,
		Bits:       bits[:24],
		Payload: map[string]any{
			"code":   data,
			"serial": data >> 4, // 20-bit
			"button": data & 0xF,
			"te_us":  teShort,
		},
	}, nil
}
