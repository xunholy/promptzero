// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Marantec Garage Door
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~625 bps (TE ≈ 800 µs)
// Payload    : 12-bit fixed code (door code)
// Sync       : 1×TE mark + 16×TE space (≈ 800 + 12800 µs)
// Bit "1"    : 3×TE mark + 1×TE space  (2400 + 800 µs)
// Bit "0"    : 1×TE mark + 3×TE space  (800 + 2400 µs)
// Frequency  : 433.92 MHz, 868.35 MHz
// Vendor     : Marantec GmbH & Co. KG (Germany) — common in European garage doors
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/marantec.c
//   - rtl_433 src/devices/marantec.c

package protocols

import "fmt"

// Marantec decodes Marantec 12-bit fixed-code OOK/PWM frames.
type Marantec struct{}

func (p Marantec) Name() string     { return "Marantec" }
func (p Marantec) BitRate() float64 { return 625.0 }

// Decode attempts to decode a Marantec frame from the pulse sequence.
//
// Marantec encodes bits as: "1" = 3×TE mark + 1×TE space, "0" = 1×TE mark +
// 3×TE space. The sync is a short mark followed by a long space (≥14×TE).
func (p Marantec) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 400, 1600)
	if !ok {
		return Result{}, fmt.Errorf("marantec: cannot estimate TE")
	}

	// Sync: short mark (≈1×TE) + long space (≥14×TE)
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(space) >= 14*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("marantec: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 12)
	if len(bits) < 12 {
		return Result{}, fmt.Errorf("marantec: only %d bits decoded", len(bits))
	}

	code := bitsToUint32(bits[:12])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:12],
		Payload: map[string]any{
			"code":  code,
			"te_us": te,
		},
	}, nil
}
