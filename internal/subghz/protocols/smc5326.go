// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: SMC5326 (PT2262-family tri-state encoder)
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~370 bps (te_short 300 µs, te_long 900 µs = 3×TE)
// Payload    : 25-bit code -> 16-bit address (8 tri-state DIP positions) + button bits
// Header     : ~24×te_short space (~7.2 ms) (inter-frame gap) + a guard mark
// Bit "0"    : te_short mark + te_long space   (300 + 900 µs)
// Bit "1"    : te_long mark + te_short space   (900 + 300 µs)
// Frequency  : 315 / 433.92 MHz
// Vendor     : standard PT2262-compatible encoder chip (cheap remotes / sensors)
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/smc5326.c
//     (te_short=300, te_long=900, te_delta=200, min_count_bit=25; the encoder
//     get_upload mark-first bit loop + the decoder feed loop + get_string,
//     where address = (data >> 9) & 0xFFFF)

package protocols

import "fmt"

// SMC5326 decodes SMC5326 (PT2262-family) 25-bit fixed-code OOK/PWM frames.
type SMC5326 struct{}

func (p SMC5326) Name() string     { return "SMC5326" }
func (p SMC5326) BitRate() float64 { return 370.0 }

// Decode attempts to decode an SMC5326 frame from the pulse sequence.
//
// Each bit is a mark followed by a space (mark-first): bit 0 = short mark + long
// space, bit 1 = long mark + short space (te_long = 3×te_short). The frame is
// preceded by a long (~24×TE) inter-frame gap space. The 25-bit code yields a
// 16-bit address (data>>9, eight tri-state DIP positions) and the low button
// bits.
func (p SMC5326) Decode(pulses []int) (Result, error) {
	// Both 1×TE and 3×TE appear ~equally per bit, so estimateTEMin (smallest
	// recurring bucket) reliably yields te_short; the naive estimator could tie.
	te, ok := estimateTEMin(pulses, 150, 1200)
	if !ok {
		return Result{}, fmt.Errorf("smc5326: cannot estimate TE")
	}

	// Sync: a long inter-frame gap space (≥15×TE), after which the bits begin.
	start := -1
	for i := 0; i < len(pulses); i++ {
		if pulses[i] < 0 && abs32(pulses[i]) >= 15*te {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("smc5326: sync not found")
	}

	// Read 25 bits, each a (mark, space) pair.
	bits := make([]byte, 0, 25)
	matched := 0
	i := start
	for len(bits) < 25 && i+1 < len(pulses) {
		if pulses[i] <= 0 || pulses[i+1] >= 0 {
			break
		}
		mk := pulses[i]
		sp := abs32(pulses[i+1])
		switch {
		case nearRatio(mk, te, 67) && nearRatio(sp, 3*te, 67):
			bits = append(bits, 0)
			matched++
		case nearRatio(mk, 3*te, 67) && nearRatio(sp, te, 67):
			bits = append(bits, 1)
			matched++
		default:
			i = len(pulses) // stop
			continue
		}
		i += 2
	}
	if len(bits) < 25 {
		return Result{}, fmt.Errorf("smc5326: only %d bits decoded", len(bits))
	}

	code := bitsToUint(bits[:25])
	address := (code >> 9) & 0xFFFF

	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 25.0,
		Bits:       bits[:25],
		Payload: map[string]any{
			"code":    code,
			"address": address,
			"te_us":   te,
		},
	}, nil
}
