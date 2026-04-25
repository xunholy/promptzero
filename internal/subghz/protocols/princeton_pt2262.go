// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Princeton PT2262
//
// Modulation : OOK, Pulse Width Modulation (PWM)
// Bit rate   : ~1000–4000 bps (TE 200–800 µs, nominal 350 µs)
// Payload    : 12-bit address + 4-bit data = 16 bits per frame
// Sync       : 1×TE mark + 31×TE space
// Bit "1"    : 3×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 3×TE space
// Frequency  : 315 MHz or 433.92 MHz
// Vendor     : Princeton Technology Corp (Taiwan)
//
// References:
//   - Princeton Technology PT2262 datasheet, revision 1.6
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/princeton.c
//   - DarkFlippers/unleashed-firmware (same file)

package protocols

import (
	"fmt"
)

// PrincetonPT2262 decodes Princeton PT2262 OOK/PWM frames.
type PrincetonPT2262 struct{}

// Name returns the protocol name.
func (p PrincetonPT2262) Name() string { return "Princeton PT2262" }

// BitRate returns the nominal bit rate in baud.
func (p PrincetonPT2262) BitRate() float64 { return 1000.0 }

// Decode attempts to decode a Princeton PT2262 frame from the pulse sequence.
//
// The decoder:
//  1. Detects TE by finding the most common short mark pulse.
//  2. Locates the sync pulse (1×TE mark + ≥25×TE space).
//  3. Decodes 16 bits from the PWM-encoded data (3×TE = 1, 1×TE = 0).
//  4. Splits into 12-bit address and 4-bit data.
func (p PrincetonPT2262) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 100, 2000)
	if !ok {
		return Result{}, fmt.Errorf("princeton: cannot estimate TE")
	}

	// Find sync: a short mark (≈1×TE) followed by a long space (≥25×TE).
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(-space) >= 20*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 || start+32 > len(pulses) {
		return Result{}, fmt.Errorf("princeton: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 16)
	if len(bits) < 16 {
		return Result{}, fmt.Errorf("princeton: insufficient bits %d", len(bits))
	}

	addr := bitsToUint(bits[:12])
	data := bitsToUint(bits[12:16])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:16],
		Payload: map[string]any{
			"address": addr,
			"data":    data,
			"te_us":   te,
		},
	}, nil
}
