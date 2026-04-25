// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Aprimatic
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000 bps (TE ≈ 500 µs)
// Payload    : 24-bit fixed code
// Sync       : 1×TE mark + 32×TE space
// Bit "1"    : 3×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 3×TE space
// Frequency  : 433.92 MHz
// Vendor     : Aprimatic S.r.l. (Italy/Spain)
//
// Aprimatic is an Italian gate/barrier manufacturer. The protocol uses
// Princeton-style PWM encoding with a 24-bit payload.
//
// References:
//   - Aprimatic remote compatibility documentation
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/aprimatic.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/aprimatic.c

package protocols

import "fmt"

// Aprimatic decodes Aprimatic 24-bit OOK/PWM frames.
type Aprimatic struct{}

func (p Aprimatic) Name() string      { return "Aprimatic" }
func (p Aprimatic) BitRate() float64  { return 1000.0 }

// Decode attempts to decode an Aprimatic frame.
func (p Aprimatic) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 1200)
	if !ok {
		return Result{}, fmt.Errorf("aprimatic: cannot estimate TE")
	}

	// Sync: 1×TE mark + ≥25×TE space
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(space) >= 25*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("aprimatic: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 24)
	if len(bits) < 24 {
		return Result{}, fmt.Errorf("aprimatic: only %d bits decoded", len(bits))
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
