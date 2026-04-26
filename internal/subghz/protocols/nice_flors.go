// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: NICE FloR-S
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000 bps (TE ≈ 500 µs)
// Payload    : 52 bits total
//              bits 0..3   — button code (4 bits)
//              bits 4..35  — 32-bit KeeLoq encrypted hopping code
//              bits 36..51 — 16-bit serial number (fixed part)
// Sync       : 1×TE mark + 36×TE space
// Bit "1"    : 1×TE mark + 3×TE space
// Bit "0"    : 3×TE mark + 1×TE space (inverted vs Princeton)
// Frequency  : 433.92 MHz
// Vendor     : NICE S.p.A. (Italy)
//
// NICE FloR-S is a KeeLoq-based rolling-code protocol. This decoder
// identifies the frame and extracts fields; full key recovery requires
// the keeloq package.
//
// References:
//   - NICE S.p.A. FloR-S product documentation
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/nice_flors.c
//   - DarkFlippers/unleashed-firmware (same)

package protocols

import "fmt"

// NICEFlorS decodes NICE FloR-S 52-bit rolling-code frames.
type NICEFlorS struct{}

func (p NICEFlorS) Name() string     { return "NICE FloR-S" }
func (p NICEFlorS) BitRate() float64 { return 1000.0 }

// Decode attempts to decode a NICE FloR-S frame.
func (p NICEFlorS) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 1200)
	if !ok {
		return Result{}, fmt.Errorf("nice_flors: cannot estimate TE")
	}

	// Sync: 1×TE mark + long space (≥25×TE)
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
		return Result{}, fmt.Errorf("nice_flors: sync not found")
	}

	// NICE FloR-S uses inverted PWM vs Princeton:
	// "0" = 3×TE mark + 1×TE space, "1" = 1×TE mark + 3×TE space
	bits := make([]byte, 0, 52)
	i := start
	matched := 0
	for len(bits) < 52 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		sp := abs32(space)
		if nearRatio(mark, te, 60) && nearRatio(sp, 3*te, 60) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(mark, 3*te, 60) && nearRatio(sp, te, 60) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 52 {
		return Result{}, fmt.Errorf("nice_flors: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 52.0

	button := bitsToUint(bits[0:4])
	hopping := bitsToUint32(bits[4:36])
	serial := bitsToUint(bits[36:52])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:52],
		Payload: map[string]any{
			"button":       button,
			"hopping_code": hopping,
			"serial":       serial,
			"te_us":        te,
		},
	}, nil
}
