// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: BFT Mitto
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1250 bps (TE ≈ 400 µs)
// Payload    : 12-bit fixed code (some variants use 10 bits)
// Sync       : 1×TE mark + 36×TE space (≈ 400 + 14400 µs)
// Bit "1"    : 3×TE mark + 1×TE space  (1200 + 400 µs)
// Bit "0"    : 1×TE mark + 3×TE space  (400 + 1200 µs)
// Frequency  : 433.92 MHz, 306.0 MHz
// Vendor     : BFT S.p.A. (Italy) — Mitto 2, Mitto 4 remotes
//
// BFT Mitto is a fixed-code OOK/PWM protocol common in European gates
// and barriers. The bit encoding is standard PWM (same as Nice FLO)
// but with a shorter TE (~400 µs vs ~700 µs).
//
// References:
//   - BFT S.p.A. Mitto remote technical documentation
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/bft_mitto.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/bft_mitto.c

package protocols

import "fmt"

// BFTMitto decodes BFT Mitto 12-bit fixed-code OOK/PWM frames.
type BFTMitto struct{}

func (p BFTMitto) Name() string     { return "BFT Mitto" }
func (p BFTMitto) BitRate() float64 { return 1250.0 }

// Decode attempts to decode a BFT Mitto frame from the pulse sequence.
//
// BFT Mitto encodes bits as: "1" = 3×TE mark + 1×TE space, "0" = 1×TE mark +
// 3×TE space. The sync is a short mark followed by a long space (≥30×TE).
func (p BFTMitto) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 800)
	if !ok {
		return Result{}, fmt.Errorf("bft_mitto: cannot estimate TE")
	}

	// Sync: short mark (≈1×TE) + long space (≥30×TE)
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(space) >= 30*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("bft_mitto: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 12)
	if len(bits) < 12 {
		return Result{}, fmt.Errorf("bft_mitto: only %d bits decoded", len(bits))
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
