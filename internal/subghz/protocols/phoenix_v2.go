// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Phoenix V2
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000 bps (TE ≈ 433 µs)
// Payload    : 12-bit fixed code
// Sync       : 1×TE mark + 32×TE space
// Bit "1"    : 3×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 3×TE space
// Frequency  : 433.92 MHz
// Vendor     : Phoenix (Italy/EU)
//
// Phoenix V2 uses the same Princeton-style PWM encoding but targets a
// different 12-bit address space than PT2262. The TE is typically around
// 430–440 µs, slightly larger than the typical Princeton TE.
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/phoenix_v2.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/phoenix_v2.c

package protocols

import "fmt"

// PhoenixV2 decodes Phoenix V2 12-bit OOK/PWM frames.
type PhoenixV2 struct{}

func (p PhoenixV2) Name() string      { return "Phoenix V2" }
func (p PhoenixV2) BitRate() float64  { return 1000.0 }

// Decode attempts to decode a Phoenix V2 frame.
// Uses Princeton-style PWM decoding with TE range tuned to 300–700 µs.
func (p PhoenixV2) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 300, 700)
	if !ok {
		return Result{}, fmt.Errorf("phoenix_v2: cannot estimate TE")
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
	if start < 0 || start+24 > len(pulses) {
		return Result{}, fmt.Errorf("phoenix_v2: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 12)
	if len(bits) < 12 {
		return Result{}, fmt.Errorf("phoenix_v2: only %d bits decoded", len(bits))
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
