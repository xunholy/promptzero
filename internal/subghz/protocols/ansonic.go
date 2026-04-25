// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Ansonic
//
// Modulation : OOK with Manchester encoding
// Bit rate   : ~1200 bps (TE ≈ 400 µs)
// Payload    : 12-bit fixed code
// Preamble   : ≥8 half-symbols of alternating polarity (Manchester preamble)
// Sync       : long mark (≥10×TE) then long space (≥10×TE)
// Encoding   : Manchester — "1" = mark+space, "0" = space+mark (IEEE 802.3)
// Frequency  : 433.92 MHz, 868 MHz
// Vendor     : Ansonic (clone/derivative of AS2260R)
//
// Ansonic remotes are widely cloned in the EU/Asian market. The protocol
// is a Manchester-encoded variant of the Princeton/Holtek 12-bit OOK family.
//
// References:
//   - Ansonic AS2260R/AS2262R datasheet
//   - rtl_433 src/devices/ansonic.c
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/ansonic.c

package protocols

import "fmt"

// Ansonic decodes Ansonic 12-bit Manchester-encoded OOK frames.
type Ansonic struct{}

func (p Ansonic) Name() string      { return "Ansonic" }
func (p Ansonic) BitRate() float64  { return 1200.0 }

// Decode attempts to decode an Ansonic frame.
func (p Ansonic) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 150, 800)
	if !ok {
		return Result{}, fmt.Errorf("ansonic: cannot estimate TE")
	}

	// Find sync: long mark (≥8×TE) followed by long space (≥8×TE)
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if abs32(mark) >= 8*te && abs32(space) >= 8*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("ansonic: sync not found")
	}

	// Manchester decode: pairs of (mark, space) or (space, mark)
	bits := make([]byte, 0, 12)
	i := start
	matched := 0
	for len(bits) < 12 && i+1 < len(pulses) {
		a := pulses[i]
		b := pulses[i+1]
		absA := abs32(a)
		absB := abs32(b)
		// Both must be half-symbol width
		if !nearRatio(absA, te, 70) || !nearRatio(absB, te, 70) {
			break
		}
		if a > 0 && b < 0 {
			bits = append(bits, 1) // mark then space = 1
			matched++
		} else if a < 0 && b > 0 {
			bits = append(bits, 0) // space then mark = 0
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 12 {
		return Result{}, fmt.Errorf("ansonic: only %d bits decoded", len(bits))
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
