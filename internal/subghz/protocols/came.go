// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: CAME
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1200 bps (TE ≈ 320 µs)
// Payload    : 12-bit fixed code
// Sync       : 1×TE mark + 36×TE space (≈ 11.5 ms space)
// Bit "1"    : 1×TE mark + 1×TE space  (320+320 µs)
// Bit "0"    : 1×TE mark + 2×TE space  (320+640 µs)
// Frequency  : 433.92 MHz (EU), 30.875 MHz (IT legacy)
// Vendor     : CAME S.p.A. (Italy)
//
// References:
//   - CAME remote protocol community documentation
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/came.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/came.c

package protocols

import "fmt"

// CAME decodes CAME 12-bit fixed-code OOK frames.
type CAME struct{}

func (p CAME) Name() string      { return "CAME" }
func (p CAME) BitRate() float64  { return 1200.0 }

// Decode attempts to decode a CAME frame from the pulse sequence.
//
// CAME encodes bits as: "1" = short mark + short space, "0" = short mark +
// long space. The sync is a long space preceded by a short mark.
func (p CAME) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 150, 700)
	if !ok {
		return Result{}, fmt.Errorf("came: cannot estimate TE")
	}

	// Sync: short mark (≈1×TE) + long space (≥30×TE)
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
		return Result{}, fmt.Errorf("came: sync not found")
	}

	// Decode 12 bits: each bit = mark(≈TE) + space(≈TE for 1 or ≈2×TE for 0)
	bits := make([]byte, 0, 12)
	i := start
	confidence := 0.0
	matched := 0
	for len(bits) < 12 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		if !nearRatio(mark, te, 60) {
			break
		}
		sp := abs32(space)
		if nearRatio(sp, te, 60) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(sp, 2*te, 60) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 12 {
		return Result{}, fmt.Errorf("came: only %d bits decoded", len(bits))
	}
	confidence = float64(matched) / 12.0
	code := bitsToUint(bits[:12])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:12],
		Payload: map[string]any{
			"code": code,
			"te_us": te,
		},
	}, nil
}
