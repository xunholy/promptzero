// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Linear MegaCode (MegaCode)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware C
// decoder/encoder; no third-party dependency, no shell-out. Decode-only here
// (passive identification); pulse generation is exercised only by the test.
//
// Modulation : OOK, pulse-position within a fixed 6×TE bit frame
// Bit rate   : 1000 baud (te_short = te_long = 1000 µs)
// Payload    : 24-bit static code, MSB-first, start bit (MSB) always 1.
//              data[23]   = start bit (1)
//              data[22:19] = 4-bit facility code
//              data[18:3]  = 16-bit serial / remote key
//              data[2:0]   = 3-bit button
// Framing    : each 6 ms frame carries a single 1 ms mark; the mark position
//              encodes the bit (bit 1 -> mark at frame end, bit 0 -> mark at
//              frame third). On air this collapses to a constant 1×TE mark
//              separated by an inter-mark space whose width encodes the
//              (prev,cur) bit pair:
//                  (1,1)=5×TE  (1,0)=2×TE  (0,1)=8×TE  (0,0)=5×TE
//              The Flipper decoder normalises this by subtracting 3×TE from the
//              space when the previous bit was 0, then classifies 5×TE->1,
//              2×TE->0. A leading guard space of 11×TE (last bit 1) or 14×TE
//              (last bit 0) precedes the transmission; a space ≥10×TE ends it.
// Frequency  : 315 MHz (AM)
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/megacode.c
//     (te_short=1000, te_delta=200, min_count_bit=24; the feed() decoder state
//     machine, get_upload() encoder, and check_remote_controller() field split)
//   - https://wiki.cuvoodoo.info/doku.php?id=megacode

package protocols

import "fmt"

// Megacode decodes Linear MegaCode 24-bit fixed-code OOK frames.
type Megacode struct{}

func (p Megacode) Name() string     { return "MegaCode" }
func (p Megacode) BitRate() float64 { return 1000.0 }

// megacodeTE is the fixed timing element (te_short). MegaCode pins both the
// short and long element to 1000 µs, so no estimation is needed — the firmware
// classifies against this constant with fixed deltas, and so do we.
const megacodeTE = 1000

// Decode attempts to decode a Linear MegaCode frame from the pulse sequence.
//
// It locates the leading guard space (≈11–14×TE, accepted 9.6–16.4 ms per the
// firmware delta), then reads 24 MSB-first bits where every mark is ≈1×TE and
// the preceding space — adjusted by −3×TE when the previous bit was 0 — selects
// the bit: ≈5×TE -> 1, ≈2×TE -> 0. The start bit (MSB) must be 1.
func (p Megacode) Decode(pulses []int) (Result, error) {
	const te = megacodeTE

	// Locate header: a guard space (negative) of 9.6–16.4 ms immediately
	// followed by the 1×TE start-bit mark.
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		sp := pulses[i]
		mk := pulses[i+1]
		if sp < 0 && abs32(sp) >= 9600 && abs32(sp) <= 16400 &&
			mk > 0 && abs32(mk) >= 800 && abs32(mk) <= 1200 {
			// start indexes the start-bit mark (the pulse after the guard).
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("megacode: header not found")
	}

	// Start bit (MSB) is always 1.
	bits := make([]byte, 0, 24)
	bits = append(bits, 1)
	lastBit := 1
	matched := 1

	// Read the remaining 23 bits as (space, mark) pairs.
	i := start + 1
	for len(bits) < 24 && i+1 < len(pulses) {
		space := pulses[i]
		mark := pulses[i+1]
		if space >= 0 || mark <= 0 {
			break
		}
		gap := abs32(space)
		// A space ≥10×TE is the end-of-frame / reset guard; not an inter-bit gap.
		if gap >= 10000 {
			break
		}
		// The mark must be ≈1×TE.
		if !nearRatio(mark, te, 25) {
			break
		}

		// Firmware normalisation: subtract 3×TE from the space when the previous
		// bit was 0, then classify against 5×TE (->1) and 2×TE (->0).
		teLast := gap
		if lastBit == 0 {
			teLast -= 3000
		}
		switch {
		case teLast >= 4000 && teLast <= 6000:
			bits = append(bits, 1)
			lastBit = 1
			matched++
		case teLast >= 1600 && teLast <= 2400:
			bits = append(bits, 0)
			lastBit = 0
			matched++
		default:
			// Unrecognised gap — stop scanning by exhausting the index.
			i = len(pulses)
			continue
		}
		i += 2
	}
	if len(bits) < 24 {
		return Result{}, fmt.Errorf("megacode: only %d bits decoded", len(bits))
	}

	data := bitsToUint(bits[:24])
	// Per check_remote_controller: valid only when the start bit (MSB) is 1.
	if data>>23 != 1 {
		return Result{}, fmt.Errorf("megacode: start bit not set")
	}
	serial := (data >> 3) & 0xFFFF
	facility := (data >> 19) & 0x0F
	button := data & 0x07

	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 24.0,
		Bits:       bits[:24],
		Payload: map[string]any{
			"code":     data,
			"serial":   serial,
			"facility": facility,
			"button":   button,
			"te_us":    te,
		},
	}, nil
}
