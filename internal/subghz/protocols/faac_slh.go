// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: FAAC SLH
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1200 bps (TE ≈ 255 µs)
// Payload    : 64 bits
//              bits 0..31  — 32-bit KeeLoq hopping code
//              bits 32..63 — 32-bit fixed code (serial + button)
// Preamble   : 1×TE mark
// Sync       : 1×TE mark + 10×TE space
// Bit "1"    : 1×TE mark + 2×TE space
// Bit "0"    : 2×TE mark + 1×TE space
// Frequency  : 433.92 MHz
// Vendor     : FAAC S.p.A. (Italy)
//
// FAAC SLH ("Smart Learning High security") is a KeeLoq-based protocol
// used in FAAC gate and barrier actuators manufactured after ~2001.
//
// References:
//   - FAAC Group technical notes (SLH protocol)
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/faac_slh.c
//   - DarkFlippers/unleashed-firmware (same)

package protocols

import "fmt"

// FaacSLH decodes FAAC SLH 64-bit rolling-code frames.
type FaacSLH struct{}

func (p FaacSLH) Name() string      { return "FAAC SLH" }
func (p FaacSLH) BitRate() float64  { return 1200.0 }

// Decode attempts to decode a FAAC SLH frame.
func (p FaacSLH) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 100, 600)
	if !ok {
		return Result{}, fmt.Errorf("faac_slh: cannot estimate TE")
	}

	// Sync: 1×TE mark + ≥8×TE space
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(space) >= 8*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("faac_slh: sync not found")
	}

	// "1" = 1×TE mark + 2×TE space; "0" = 2×TE mark + 1×TE space
	bits := make([]byte, 0, 64)
	i := start
	matched := 0
	for len(bits) < 64 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		sp := abs32(space)
		if nearRatio(mark, te, 60) && nearRatio(sp, 2*te, 60) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(mark, 2*te, 60) && nearRatio(sp, te, 60) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 64 {
		return Result{}, fmt.Errorf("faac_slh: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 64.0

	hopping := bitsToUint32(bits[0:32])
	fixed := bitsToUint32(bits[32:64])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:64],
		Payload: map[string]any{
			"hopping_code": hopping,
			"fixed_code":   fixed,
			"te_us":        te,
		},
	}, nil
}
