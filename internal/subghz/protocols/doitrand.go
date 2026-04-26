// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Doitrand
//
// Modulation : OOK, Pulse Distance Modulation
// Bit rate   : ~1000 bps (TE ≈ 400 µs)
// Payload    : 12-bit fixed code
// Sync       : long space (≥20×TE)
// Bit "1"    : 1×TE mark + 3×TE space
// Bit "0"    : 1×TE mark + 1×TE space
// Frequency  : 433.92 MHz
// Vendor     : Doitrand (France)
//
// Doitrand is a French gate/barrier brand. The protocol is PDM-encoded
// and closely resembles CAME but with different bit encoding ratios.
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/doitrand.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/doitrand.c

package protocols

import "fmt"

// Doitrand decodes Doitrand 12-bit OOK frames.
type Doitrand struct{}

func (p Doitrand) Name() string     { return "Doitrand" }
func (p Doitrand) BitRate() float64 { return 1000.0 }

// Decode attempts to decode a Doitrand frame.
// Uses midpoint discrimination (2×TE threshold) to separate "1" (3×TE space)
// from "0" (1×TE space), which avoids false matches from wide tolerances.
func (p Doitrand) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 150, 900)
	if !ok {
		return Result{}, fmt.Errorf("doitrand: cannot estimate TE")
	}

	// Sync: long space ≥18×TE
	start := -1
	for i := 0; i < len(pulses); i++ {
		sp := pulses[i]
		if sp < 0 && abs32(sp) >= 18*te {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("doitrand: sync not found")
	}

	// "1" = 1×TE mark + 3×TE space; "0" = 1×TE mark + 1×TE space
	// Discriminate at 2×TE midpoint
	midpoint := 2 * te
	bits := make([]byte, 0, 12)
	i := start
	matched := 0
	for len(bits) < 12 && i+1 < len(pulses) {
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
		// Accept spaces in range [0.5×TE, 4×TE]
		if sp < te/2 || sp > 4*te {
			break
		}
		if sp > midpoint {
			bits = append(bits, 1)
		} else {
			bits = append(bits, 0)
		}
		matched++
		i += 2
	}

	if len(bits) < 12 {
		return Result{}, fmt.Errorf("doitrand: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 12.0
	code := bitsToUint(bits[:12])

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
