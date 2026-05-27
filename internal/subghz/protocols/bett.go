// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: BETT (Barrier/Gate controller)
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1250 bps (TE ≈ 400 µs)
// Payload    : 18-bit code (DIP switch configuration)
// Sync       : 1×TE mark + 45×TE space (≈ 400 + 18000 µs)
// Bit "1"    : 3×TE mark + 1×TE space  (1200 + 400 µs)
// Bit "0"    : 1×TE mark + 3×TE space  (400 + 1200 µs)
// Frequency  : 433.92 MHz
// Vendor     : Various manufacturers — common in Italian/European barrier systems
//
// The 18 bits correspond to 9 DIP switches, each represented by 2 bits:
//   00 = OFF, 11 = ON, 01 = Float, 10 = Float
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/bett.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/bett.c

package protocols

import "fmt"

// BETT decodes BETT 18-bit DIP-switch OOK/PWM frames.
type BETT struct{}

func (p BETT) Name() string     { return "BETT" }
func (p BETT) BitRate() float64 { return 1250.0 }

// Decode attempts to decode a BETT frame from the pulse sequence.
//
// BETT encodes bits as: "1" = 3×TE mark + 1×TE space, "0" = 1×TE mark +
// 3×TE space. The sync is a short mark followed by a long space (≥35×TE).
func (p BETT) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 800)
	if !ok {
		return Result{}, fmt.Errorf("bett: cannot estimate TE")
	}

	// Sync: short mark (≈1×TE) + long space (≥35×TE)
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(space) >= 35*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("bett: sync not found")
	}

	bits, confidence := decodePWMBits(pulses[start:], te, 18)
	if len(bits) < 18 {
		return Result{}, fmt.Errorf("bett: only %d bits decoded", len(bits))
	}

	code := bitsToUint32(bits[:18])
	dipSwitches := decodeBETTDIPSwitches(bits[:18])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:18],
		Payload: map[string]any{
			"code":         code,
			"dip_switches": dipSwitches,
			"te_us":        te,
		},
	}, nil
}

// decodeBETTDIPSwitches decodes 9 DIP switch states from 18 bits (2 bits per switch).
// Bit pairs: 00=OFF, 11=ON, 01=Float, 10=Float.
func decodeBETTDIPSwitches(bits []byte) []string {
	states := make([]string, 9)
	for i := 0; i < 9; i++ {
		high := bits[i*2]
		low := bits[i*2+1]
		switch {
		case high == 0 && low == 0:
			states[i] = "OFF"
		case high == 1 && low == 1:
			states[i] = "ON"
		default:
			states[i] = "Float"
		}
	}
	return states
}
