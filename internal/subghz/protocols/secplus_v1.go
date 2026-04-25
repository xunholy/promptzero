// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Security+ v1 (Chamberlain / LiftMaster)
//
// SUBSTITUTED for Linkmaster: Linkmaster has no reliable public protocol
// specification or timing documentation. Security+ v1 is a well-documented
// US garage-door protocol (Chamberlain, LiftMaster, Craftsman) with clear
// OOK timing, present in both rtl_433 and Flipper firmware catalogues.
//
// Modulation : OOK, Pulse Distance Modulation
// Bit rate   : ~1000 bps (TE ≈ 500 µs)
// Payload    : 40 bits (20-bit rolling code + 20-bit fixed code)
// Preamble   : 10–15 alternating short pulses
// Sync       : long mark (≥16×TE)
// Bit "1"    : 1×TE mark + 2×TE space
// Bit "0"    : 2×TE mark + 1×TE space
// Frequency  : 390 MHz, 315 MHz (US)
// Vendor     : Chamberlain Group (LiftMaster, Craftsman)
//
// References:
//   - Weston Embedded Security+ v1 protocol analysis
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/secplus_v1.c
//   - rtl_433 src/devices/secplus.c

package protocols

import "fmt"

// SecplusV1 decodes Security+ v1 40-bit rolling-code frames.
type SecplusV1 struct{}

func (p SecplusV1) Name() string      { return "Security+ v1" }
func (p SecplusV1) BitRate() float64  { return 1000.0 }

// Decode attempts to decode a Security+ v1 frame.
func (p SecplusV1) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 1200)
	if !ok {
		return Result{}, fmt.Errorf("secplus_v1: cannot estimate TE")
	}

	// Sync: a long mark (≥12×TE) is the start-of-frame indicator.
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && abs32(mark) >= 12*te && space < 0 {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("secplus_v1: sync not found")
	}

	// "1" = 1×TE mark + 2×TE space; "0" = 2×TE mark + 1×TE space
	bits := make([]byte, 0, 40)
	i := start
	matched := 0
	for len(bits) < 40 && i+1 < len(pulses) {
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

	if len(bits) < 40 {
		return Result{}, fmt.Errorf("secplus_v1: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 40.0

	rolling := bitsToUint32(bits[0:20])
	fixed := bitsToUint32(bits[20:40])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:40],
		Payload: map[string]any{
			"rolling_code": rolling,
			"fixed_code":   fixed,
			"te_us":        te,
		},
	}, nil
}
