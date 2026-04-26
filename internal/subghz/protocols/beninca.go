// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Beninca
//
// Modulation : OOK, Pulse Width Modulation (CAME-like)
// Bit rate   : ~1200 bps (TE ≈ 320 µs)
// Payload    : 12-bit fixed code
// Sync       : 1×TE mark + 36×TE space
// Bit "1"    : 1×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 2×TE space
// Frequency  : 433.92 MHz
// Vendor     : Beninca Group (Italy)
//
// Beninca is electrically equivalent to CAME but uses a slightly different
// sync gap. Beninca and CAME remotes often operate interchangeably on the
// same receivers due to the very similar timing.
//
// References:
//   - Beninca Group product documentation
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/beninca.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/beninca.c

package protocols

import "fmt"

// Beninca decodes Beninca 12-bit fixed-code OOK frames.
type Beninca struct{}

func (p Beninca) Name() string     { return "Beninca" }
func (p Beninca) BitRate() float64 { return 1200.0 }

// Decode attempts to decode a Beninca frame.
// Timing is nearly identical to CAME; distinguished by the longer sync gap
// (≥30×TE) and slightly different TE range.
func (p Beninca) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 200, 600)
	if !ok {
		return Result{}, fmt.Errorf("beninca: cannot estimate TE")
	}

	// Sync: 1×TE mark + ≥28×TE space
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 60) && abs32(space) >= 28*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("beninca: sync not found")
	}

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
		return Result{}, fmt.Errorf("beninca: only %d bits decoded", len(bits))
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
