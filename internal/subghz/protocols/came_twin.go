// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: CAME TWIN
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1200 bps (TE ≈ 320 µs) — same as CAME but different sync
// Payload    : 12-bit fixed code
// Sync       : 2×TE mark + 36×TE space (vs CAME's 1×TE mark sync)
// Bit "1"    : 1×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 2×TE space
// Frequency  : 433.92 MHz
// Vendor     : CAME S.p.A. (Italy) — TWIN receiver series
//
// CAME TWIN is the CAME protocol variant used with the CAME TWIN radio
// receivers. It differs from the standard CAME 12-bit protocol only in the
// sync gap mark duration (2×TE instead of 1×TE).
//
// References:
//   - CAME S.p.A. TWIN receiver documentation
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/came_tw.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/came_tw.c

package protocols

import "fmt"

// CAMETwin decodes CAME TWIN 12-bit OOK frames.
type CAMETwin struct{}

func (p CAMETwin) Name() string     { return "CAME TWIN" }
func (p CAMETwin) BitRate() float64 { return 1200.0 }

// Decode attempts to decode a CAME TWIN frame.
// Distinguished from standard CAME by the 2×TE sync mark.
func (p CAMETwin) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 150, 700)
	if !ok {
		return Result{}, fmt.Errorf("came_twin: cannot estimate TE")
	}

	// Sync: 2×TE mark + ≥28×TE space
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, 2*te, 60) && abs32(space) >= 28*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("came_twin: sync not found")
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
		return Result{}, fmt.Errorf("came_twin: only %d bits decoded", len(bits))
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
