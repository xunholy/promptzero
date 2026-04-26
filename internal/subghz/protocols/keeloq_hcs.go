// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: KeeLoq HCS200/300/360/410
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000–2500 bps (TE ≈ 200–500 µs, nominal 400 µs)
// Payload    : 66 bits total
//              bits 0..31  — 32-bit KeeLoq encrypted hopping code (LSB first)
//              bits 32..63 — 32-bit serial number (LSB first)
//              bits 64..66 — button code (2 bits for HCS200, 4 for HCS300+)
// Preamble   : 12 full marks of TE each (pilot pulses)
// Sync       : 1×TE mark + 10×TE space (header)
// Bit encoding: PWM — "1" = 3×TE mark + 1×TE space, "0" = 1×TE mark + 3×TE space
// Frequency  : 433.92 MHz, 315 MHz
// Vendor     : Microchip Technology (originally Nanoteq)
//
// References:
//   - Microchip Technology AN66115 "Code Hopping Decoder Using the HCS301"
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/keeloq.c

package protocols

import "fmt"

// KeeLoqHCS decodes Microchip HCS-series KeeLoq rolling-code frames.
type KeeLoqHCS struct{}

func (p KeeLoqHCS) Name() string     { return "KeeLoq HCS200/300" }
func (p KeeLoqHCS) BitRate() float64 { return 2500.0 }

// Decode attempts to decode a KeeLoq HCS frame.
//
// Pilot tone: 12 short marks. Header: 1×TE mark + 10×TE space.
// Then 66 bits PWM (bit 0 = LSB of hopping code transmitted first).
func (p KeeLoqHCS) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 100, 800)
	if !ok {
		return Result{}, fmt.Errorf("keeloq: cannot estimate TE")
	}

	// Locate header: 1×TE mark + ≥8×TE space (after pilot pulses)
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
		return Result{}, fmt.Errorf("keeloq: header not found")
	}

	// 66 bits: "1" = 3×TE mark + 1×TE space, "0" = 1×TE mark + 3×TE space
	bits := make([]byte, 0, 66)
	i := start
	matched := 0
	for len(bits) < 66 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		sp := abs32(space)
		if nearRatio(mark, 3*te, 60) && nearRatio(sp, te, 60) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(mark, te, 60) && nearRatio(sp, 3*te, 60) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 64 {
		return Result{}, fmt.Errorf("keeloq: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 66.0

	// LSB-first: reverse 32-bit groups for display
	hopping := bitsToUint32LSBFirst(bits[0:32])
	serial := bitsToUint32LSBFirst(bits[32:64])
	var button uint32
	if len(bits) >= 66 {
		button = bitsToUint(bits[64:66])
	}

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits,
		Payload: map[string]any{
			"hopping_code": hopping,
			"serial":       serial,
			"button":       button,
			"te_us":        te,
		},
	}, nil
}
