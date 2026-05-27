// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Nice FLO
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~714 bps (TE ≈ 700 µs)
// Payload    : 12-bit fixed code
// Sync       : 1×TE mark + 36×TE space (≈ 700 + 25200 µs)
// Bit "1"    : 3×TE mark + 1×TE space  (2100 + 700 µs)
// Bit "0"    : 1×TE mark + 3×TE space  (700 + 2100 µs)
// Frequency  : 433.92 MHz (EU)
// Vendor     : Nice S.p.A. (Italy) — FLO1, FLO2, FLO4 remotes
//
// Nice FLO is the fixed-code variant of the Nice rolling-code family.
// It is common in European gates and garage doors. The rolling-code
// variant (Nice FLOR-S) is a separate protocol.
//
// References:
//   - Nice S.p.A. FLO system technical documentation
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/nice_flo.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/nice_flo.c

package protocols

import "fmt"

// NiceFLO decodes Nice FLO 12-bit fixed-code OOK/PWM frames.
type NiceFLO struct{}

func (p NiceFLO) Name() string     { return "Nice FLO" }
func (p NiceFLO) BitRate() float64 { return 714.0 }

// Decode attempts to decode a Nice FLO frame from the pulse sequence.
//
// Nice FLO encodes bits as: "1" = 3×TE mark + 1×TE space, "0" = 1×TE mark +
// 3×TE space. The sync is a short mark followed by a long space (≥30×TE).
func (p NiceFLO) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 300, 1500)
	if !ok {
		return Result{}, fmt.Errorf("nice_flo: cannot estimate TE")
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
		return Result{}, fmt.Errorf("nice_flo: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 12)
	if len(bits) < 12 {
		return Result{}, fmt.Errorf("nice_flo: only %d bits decoded", len(bits))
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
