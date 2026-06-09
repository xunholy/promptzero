// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Dooya (motorised blind / shutter / curtain remotes)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware decoder;
// no third-party dependency, no shell-out. Decode-only (passive identification).
//
// Dooya is the dominant motor/remote brand for powered window coverings (sold
// under many smart-home labels); the remote is OOK / PWM at 433.92 MHz.
//
// Modulation : OOK, Pulse Width Modulation
// Timing     : te_short 366 µs, te_long 733 µs (= 2×te_short), te_delta 120 µs
// Header     : a 13×te_short (~4758 µs) guard mark + 2×te_long space precedes
//              the 40 data bits.
// Payload    : 40-bit code, MSB-first:
//                serial  = code >> 16        (24-bit remote serial)
//                chan-md = (code >> 12) & 0xF (0 = single, 1 = multi channel)
//                channel = (code >> 8)  & 0xF
//                key     = code & 0xFF        (button, named per the table)
// Bit "1"    : te_long mark + te_short space
// Bit "0"    : te_short mark + te_long space
// Frequency  : 433.92 MHz
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/dooya.c
//     (te_short=366, te_long=733, te_delta=120, min_count_bit_for_found=40; the
//     feed() PWM state machine, get_upload() encoder, and the documented
//     check_remote_controller() field split + key table — verified here against
//     that file's own worked example 0xE1DC030533). Dooya carries no checksum,
//     so a frame is gated by the header sync, the 40-bit count and the per-bit
//     PWM timing; the classifier ranks it against other matches by confidence.

package protocols

import "fmt"

// dooyaButtons maps the 8-bit key field to its documented action.
var dooyaButtons = map[uint64]string{
	0x11: "long press up",
	0x1E: "short press up",
	0x33: "long press down",
	0x3C: "short press down",
	0x55: "stop",
	0x79: "up+down",
	0x80: "up+stop",
}

// Dooya decodes Dooya 40-bit fixed-code OOK/PWM blind/shutter frames.
type Dooya struct{}

func (p Dooya) Name() string     { return "Dooya" }
func (p Dooya) BitRate() float64 { return 910.0 } // ~1 bit per (te_short+te_long)=1099 µs

// Decode attempts to decode a Dooya frame from the pulse sequence. It syncs on
// the 13×te_short (~4758 µs) guard mark, then reads 40 MSB-first PWM bits where
// the mark length selects the bit (te_short → 0, te_long → 1).
func (p Dooya) Decode(pulses []int) (Result, error) {
	const teShort, teLong, delta = 366, 733, 180
	const headerMark = 13 * teShort // ~4758 µs guard

	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		if pulses[i] > 0 && abs32(pulses[i]-headerMark) <= 3*teShort {
			start = i + 2 // skip the guard mark and its trailing space
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("dooya: guard sync not found")
	}

	bits := make([]byte, 0, 40)
	matched := 0
	i := start
	for len(bits) < 40 && i+1 < len(pulses) {
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
			i = len(pulses)
			continue
		}
		i += 2
	}
	if len(bits) < 40 {
		return Result{}, fmt.Errorf("dooya: only %d of 40 bits decoded", len(bits))
	}

	var data uint64
	for _, b := range bits {
		data = data<<1 | uint64(b)
	}
	key := data & 0xFF
	button := dooyaButtons[key]
	if button == "" {
		button = "unknown"
	}

	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 40.0,
		Bits:       bits[:40],
		Payload: map[string]any{
			"code":         data,
			"serial":       (data >> 16) & 0xFFFFFF,
			"channel_mode": (data >> 12) & 0xF, // 0 = single, 1 = multi
			"channel":      (data >> 8) & 0xF,
			"key":          key,
			"button":       button,
			"te_us":        teShort,
		},
	}, nil
}
