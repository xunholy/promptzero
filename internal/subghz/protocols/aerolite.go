// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Aerolite (Nero Radio / Nero Sketch)
//
// SUBSTITUTED for Hormann HSM: Hormann HSM uses a proprietary BiSS-C serial
// bus with encrypted 44-bit rolling codes. No public clean-room protocol
// documentation exists. Aerolite (also marketed as Nero Radio / Nero Sketch
// in some firmware catalogues) is a well-documented Italian gate protocol
// with clear pulse timing, present in both Flipper firmware and rtl_433.
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000 bps (TE ≈ 500 µs)
// Payload    : 24-bit fixed code
// Sync       : 1×TE mark + 35×TE space
// Bit "1"    : 3×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 3×TE space
// Frequency  : 433.92 MHz
// Vendor     : Aerolite / Nero Radio (Italy)
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/nero_radio.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/nero_radio.c

package protocols

import "fmt"

// Aerolite decodes Aerolite/Nero Radio 24-bit OOK/PWM frames.
type Aerolite struct{}

func (p Aerolite) Name() string      { return "Aerolite (Nero Radio)" }
func (p Aerolite) BitRate() float64  { return 1000.0 }

// Decode attempts to decode an Aerolite frame.
func (p Aerolite) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 1200)
	if !ok {
		return Result{}, fmt.Errorf("aerolite: cannot estimate TE")
	}

	// Sync: 1×TE mark + ≥28×TE space
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(space) >= 28*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("aerolite: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 24)
	if len(bits) < 24 {
		return Result{}, fmt.Errorf("aerolite: only %d bits decoded", len(bits))
	}

	code := bitsToUint32(bits[:24])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:24],
		Payload: map[string]any{
			"code":  code,
			"te_us": te,
		},
	}, nil
}
