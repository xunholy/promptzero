// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Linear
//
// Modulation : OOK
// Bit rate   : ~1000 bps (TE ≈ 500 µs)
// Payload    : 8-bit code, transmitted 3 times
// Sync       : long space (≥20×TE) followed by data
// Bit "1"    : 1×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 3×TE space (similar to CAME)
// Frequency  : 300 MHz, 310 MHz, 315 MHz (US)
// Vendor     : Linear LLC (US), compatible with Multi-Code
//
// The Linear format is used in many US garage door remotes. The 8-bit code
// is the DIP-switch code from the remote; there is no rolling code.
//
// References:
//   - Linear LLC compatibility documentation
//   - rtl_433 src/devices/linear.c
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/linear.c

package protocols

import "fmt"

// Linear decodes Linear/Multi-Code 8-bit OOK frames.
type Linear struct{}

func (p Linear) Name() string     { return "Linear" }
func (p Linear) BitRate() float64 { return 1000.0 }

// Decode attempts to decode a Linear garage-door remote frame.
func (p Linear) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 1200)
	if !ok {
		return Result{}, fmt.Errorf("linear: cannot estimate TE")
	}

	// Sync: long space (≥15×TE) followed by data pulses.
	start := -1
	for i := 0; i < len(pulses); i++ {
		sp := pulses[i]
		if sp < 0 && abs32(sp) >= 15*te {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("linear: sync space not found")
	}

	// Decode 8 bits: mark(≈TE) + space(≈TE = 1, ≈3×TE = 0)
	bits := make([]byte, 0, 8)
	i := start
	matched := 0
	for len(bits) < 8 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		if !nearRatio(mark, te, 70) {
			break
		}
		sp := abs32(space)
		if nearRatio(sp, te, 70) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(sp, 3*te, 70) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 8 {
		return Result{}, fmt.Errorf("linear: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 8.0 * 0.9 // slight penalty vs rolling-code protocols
	code := bitsToUint(bits[:8])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:8],
		Payload: map[string]any{
			"code":  code,
			"te_us": te,
		},
	}, nil
}
