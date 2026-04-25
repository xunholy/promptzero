// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Holtek HT12E
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000–3000 bps (TE 200–600 µs, nominal 340 µs)
// Payload    : 8-bit address + 4-bit data = 12 bits per frame
// Preamble   : 36×TE low (silence / start gap)
// Sync       : 1×TE mark + 1×TE space (pilot tone)
// Bit "0"    : 1×TE mark + 3×TE space
// Bit "1"    : 3×TE mark + 1×TE space
// Frequency  : 433.92 MHz, 315 MHz
// Vendor     : Holtek Semiconductor Inc. (Taiwan)
//
// HT12E is closely related to Princeton PT2262 but has 8-bit address instead
// of 12-bit, and uses the same PWM encoding.
//
// References:
//   - Holtek HT12E encoder datasheet, revision 1.4
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/holtek.c

package protocols

import "fmt"

// HoltekHT12E decodes Holtek HT12E OOK/PWM frames.
type HoltekHT12E struct{}

func (p HoltekHT12E) Name() string      { return "Holtek HT12E" }
func (p HoltekHT12E) BitRate() float64  { return 1000.0 }

// Decode attempts to decode a Holtek HT12E frame.
// Frame structure: 12 bits (8-bit address | 4-bit data), PWM encoded.
func (p HoltekHT12E) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 100, 1000)
	if !ok {
		return Result{}, fmt.Errorf("holtek: cannot estimate TE")
	}

	// Sync: 1×TE mark + long space (≥20×TE)
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 70) && abs32(space) >= 20*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 || start+24 > len(pulses) {
		return Result{}, fmt.Errorf("holtek: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 12)
	if len(bits) < 12 {
		return Result{}, fmt.Errorf("holtek: only %d bits", len(bits))
	}

	addr := bitsToUint(bits[:8])
	data := bitsToUint(bits[8:12])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:12],
		Payload: map[string]any{
			"address": addr,
			"data":    data,
			"te_us":   te,
		},
	}, nil
}
