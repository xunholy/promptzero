// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Prastel
//
// Modulation : OOK, Pulse Distance Modulation
// Bit rate   : ~1000 bps (TE ≈ 500 µs)
// Payload    : 12-bit fixed code
// Sync       : long space (≥20×TE)
// Bit "1"    : 1×TE mark + 2×TE space
// Bit "0"    : 1×TE mark + 1×TE space
// Frequency  : 433.92 MHz
// Vendor     : Prastel S.A.S. (France)
//
// Prastel MRC12 is a fixed-code OOK protocol used in French and European
// gate and barrier systems. The bit encoding is PDM (pulse distance).
//
// References:
//   - Prastel MRC12 remote compatibility notes
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/prastel.c
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/prastel.c

package protocols

import "fmt"

// Prastel decodes Prastel MRC12 OOK frames.
type Prastel struct{}

func (p Prastel) Name() string      { return "Prastel" }
func (p Prastel) BitRate() float64  { return 1000.0 }

// Decode attempts to decode a Prastel frame.
// Uses midpoint discrimination (1.5×TE threshold) to separate "1" (2×TE space)
// from "0" (1×TE space), avoiding the false matches caused by a 70% tolerance.
func (p Prastel) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 1200)
	if !ok {
		return Result{}, fmt.Errorf("prastel: cannot estimate TE")
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
		return Result{}, fmt.Errorf("prastel: sync not found")
	}

	// "1" = 1×TE mark + 2×TE space; "0" = 1×TE mark + 1×TE space
	// Discriminate using midpoint: sp > 1.5×te → "1"; sp ≤ 1.5×te → "0"
	midpoint := te + te/2 // 1.5×TE
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
		// Accept spaces in range [0.5×TE, 3×TE] for robustness
		if sp < te/2 || sp > 3*te {
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
		return Result{}, fmt.Errorf("prastel: only %d bits decoded", len(bits))
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
