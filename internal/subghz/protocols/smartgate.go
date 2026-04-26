// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Smartgate
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~500 bps (TE ≈ 1000 µs)
// Payload    : 24-bit proprietary code
// Sync       : long space (≥30×TE)
// Bit "1"    : 2×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 2×TE space
// Frequency  : 433.92 MHz
// Vendor     : Smartgate (Australian/NZ brand, also sold as SG series)
//
// Smartgate is a proprietary fixed-code protocol from an Australian garage
// door manufacturer. The 24-bit code encodes channel and serial data.
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/smartgate.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/smartgate.c

package protocols

import "fmt"

// Smartgate decodes Smartgate 24-bit OOK frames.
type Smartgate struct{}

func (p Smartgate) Name() string     { return "Smartgate" }
func (p Smartgate) BitRate() float64 { return 500.0 }

// Decode attempts to decode a Smartgate frame.
// Uses the minimum-duration mark pulse as TE to avoid estimation bias
// when the payload contains more long marks than short marks.
func (p Smartgate) Decode(pulses []int) (Result, error) {
	// Estimate TE as the most-common short mark in [400, 2000] µs.
	te, ok := estimateTEMin(pulses, 400, 2000)
	if !ok {
		return Result{}, fmt.Errorf("smartgate: cannot estimate TE")
	}

	// Sync: long space ≥20×TE
	start := -1
	for i := 0; i < len(pulses); i++ {
		sp := pulses[i]
		if sp < 0 && abs32(sp) >= 20*te {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("smartgate: sync not found")
	}

	// "1" = 2×TE mark + 1×TE space; "0" = 1×TE mark + 2×TE space
	// Use midpoint at 1.5×TE to discriminate mark widths
	bits := make([]byte, 0, 24)
	i := start
	matched := 0
	for len(bits) < 24 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		sp := abs32(space)
		if nearRatio(mark, 2*te, 60) && nearRatio(sp, te, 60) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(mark, te, 60) && nearRatio(sp, 2*te, 60) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 24 {
		return Result{}, fmt.Errorf("smartgate: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 24.0
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
