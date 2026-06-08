// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: GangQi (Chinese alarm / gate / barrier remotes)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware decoder;
// no third-party dependency, no shell-out. Decode-only (passive identification).
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : te_short 500 µs, te_long 1200 µs, te_delta 200 µs
// Payload    : 34-bit static code, MSB-first.
//                button  = (code >> 10) & 0xF   (named per the firmware table)
//                serial  = (code >> 16) & 0xFFFFF
//                bytesum = (code >>  2) & 0xFF   (8-bit additive checksum)
// Bit "0"    : te_short mark + te_long space
// Bit "1"    : te_long mark + te_short space
// Framing    : a 2×te_long (~2400 µs) inter-frame GAP both precedes the first
//              bit and terminates the frame; the final bit's trailing space is
//              that closing gap (the firmware emits te_short×4 + te_delta).
// Checksum   : the receiver accepts two additive sums over the 16-bit serial
//              and the 0xD0|button constant — the original-remote form
//              (0xC8 − serial_hi − serial_lo − const_btn) and a "backdoor"
//              form (0x02 + serial_hi + serial_lo + const_btn). A frame whose
//              bytesum field matches neither still decodes but is confidence-
//              halved so a checksum-valid match always outranks it.
// Frequency  : 433.92 MHz (AM)
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/gangqi.c
//     (te_short=500, te_long=1200, te_delta=200, min_count_bit=34; the feed()
//     state machine, get_upload() encoder, get_string()'s sum_type1/sum_type2
//     bytesum derivation, and the get_button_name() table). Decoder added to the
//     firmware 09.2024 (@xMasterX), bytesum finalised 02.2025.

package protocols

import "fmt"

// GangQi decodes GangQi 34-bit fixed-code OOK/PWM frames.
type GangQi struct{}

func (p GangQi) Name() string     { return "GangQi" }
func (p GangQi) BitRate() float64 { return 588.0 } // ~1 bit per (te_short+te_long)

// gangqiButtonNames mirrors the firmware's get_button_name() table verbatim;
// unlisted positions read as "Unknown".
var gangqiButtonNames = [16]string{
	"Unknown", "Exit settings", "Volume setting", "0x3",
	"Vibro sens. setting", "Settings mode", "Ringtone setting", "Ring",
	"0x8", "0x9", "0xA", "Alarm",
	"0xC", "Arm", "Disarm", "0xF",
}

// Decode attempts to decode a GangQi frame from the pulse sequence.
//
// It anchors on the 2×te_long inter-frame gap, then reads 34 MSB-first PWM bits
// (te_short mark + te_long space → 0, te_long mark + te_short space → 1). The
// final bit's trailing space is the closing gap. The 8-bit bytesum field is
// validated against the firmware's two accepted additive sums; a mismatch
// halves the confidence rather than rejecting outright.
func (p GangQi) Decode(pulses []int) (Result, error) {
	const (
		teShort = 500
		teLong  = 1200
		teDelta = 200
	)
	// The firmware matches the gap with a 5×te_delta window (DURATION_DIFF <
	// te_delta*5); per-bit elements use the tight 1×te_delta window.
	gap := 2 * teLong
	gapDelta := 5 * teDelta

	within := func(v, target, delta int) bool { return abs32(v-target) <= delta }

	// Sync on the leading inter-frame gap: a space of ~2×te_long.
	start := -1
	for i := 0; i < len(pulses); i++ {
		if pulses[i] < 0 && within(abs32(pulses[i]), gap, gapDelta) {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("gangqi: sync gap not found")
	}

	// Read 34 MSB-first PWM bits; the final bit closes on the inter-frame gap.
	bits := make([]byte, 0, 34)
	matched := 0
	i := start
	for len(bits) < 34 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 || space >= 0 {
			break
		}
		m := mark
		s := abs32(space)
		switch {
		case within(m, teShort, teDelta) && within(s, teLong, teDelta):
			bits = append(bits, 0)
			matched++
			i += 2
		case within(m, teLong, teDelta) && within(s, teShort, teDelta):
			bits = append(bits, 1)
			matched++
			i += 2
		case within(s, gap, gapDelta):
			// Closing gap: the firmware derives the final bit from the mark
			// alone (short → 0, long → 1), then declares the frame found.
			switch {
			case within(m, teShort, teDelta):
				bits = append(bits, 0)
				matched++
			case within(m, teLong, teDelta):
				bits = append(bits, 1)
				matched++
			}
			i = len(pulses) // frame terminated by the gap — stop scanning
		default:
			i = len(pulses) // unrecognised element — stop
		}
	}
	if len(bits) != 34 {
		return Result{}, fmt.Errorf("gangqi: decoded %d bits, want 34", len(bits))
	}

	// 34 bits exceed uint32, so accumulate as uint64 (MSB-first).
	var data uint64
	for _, b := range bits {
		data = data<<1 | uint64(b)
	}

	btn := byte((data >> 10) & 0xF)
	serial := (data >> 16) & 0xFFFFF

	// Bytesum gate — both forms the receiver accepts (get_string sum_type1/2),
	// computed in 8-bit (uint8) arithmetic exactly as the firmware does.
	serial16 := uint16((data >> 18) & 0xFFFF)
	constAndBtn := byte(0xD0 | btn)
	serialHigh := byte(serial16 >> 8)
	serialLow := byte(serial16 & 0xFF)
	sumField := byte((data >> 2) & 0xFF)
	sum1 := byte(0xC8) - serialHigh - serialLow - constAndBtn
	sum2 := byte(0x02) + serialHigh + serialLow + constAndBtn
	checksumOK := sumField == sum1 || sumField == sum2

	confidence := float64(matched) / 34.0
	if !checksumOK {
		// Decodes structurally but fails the additive checksum — keep it
		// rankable yet always below a checksum-valid match.
		confidence *= 0.5
	}

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits,
		Payload: map[string]any{
			"code":        data,
			"serial":      serial,
			"button":      btn,
			"button_name": gangqiButtonNames[btn],
			"bytesum":     sumField,
			"checksum_ok": checksumOK,
			"te_us":       teShort,
		},
	}, nil
}
