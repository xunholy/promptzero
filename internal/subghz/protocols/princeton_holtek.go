// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Princeton-Holtek (composite clone)
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000–3000 bps (TE 200–700 µs)
// Payload    : 12 bits (variable split: 8-bit addr + 4-bit data,
//              or 12-bit addr + 0, depending on chip clone variant)
// Sync       : 1×TE mark + 31×TE space (Princeton timing)
// Bit "1"    : 3×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 3×TE space
// Frequency  : 315 MHz, 433.92 MHz
// Vendor     : Various clone manufacturers (CN/TW market)
//
// Princeton-Holtek clones use the Princeton PT2262 protocol framing but
// are sold under Holtek branding or as generic clones. This decoder is
// identical to Princeton PT2262 but tuned to accept a slightly wider TE
// range typical of clone hardware and returns confidence slightly below
// the genuine Princeton decoder to avoid false positives.
//
// References:
//   - Princeton Technology PT2262 datasheet
//   - Holtek HT12E datasheet
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/princeton.c

package protocols

import "fmt"

// PrincetonHoltek decodes Princeton-Holtek clone OOK/PWM frames.
type PrincetonHoltek struct{}

func (p PrincetonHoltek) Name() string      { return "Princeton-Holtek" }
func (p PrincetonHoltek) BitRate() float64  { return 1000.0 }

// Decode attempts to decode a Princeton-Holtek clone frame.
// Accepts a wider TE tolerance (75%) vs the genuine PT2262 decoder (60%)
// to handle clone timing drift. Confidence is capped at 0.85 to rank
// below genuine PT2262 detections.
func (p PrincetonHoltek) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 100, 2000)
	if !ok {
		return Result{}, fmt.Errorf("princeton_holtek: cannot estimate TE")
	}

	// Sync: 1×TE mark + ≥20×TE space (slightly relaxed vs genuine Princeton)
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if nearRatio(mark, te, 75) && abs32(space) >= 20*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 || start+24 > len(pulses) {
		return Result{}, fmt.Errorf("princeton_holtek: sync not found")
	}

	bits, confidence := decodePWMBitsRelaxed(pulses[start:], te, 12, 75)
	if len(bits) < 12 {
		return Result{}, fmt.Errorf("princeton_holtek: only %d bits decoded", len(bits))
	}
	// Cap confidence to distinguish from genuine Princeton PT2262.
	if confidence > 0.85 {
		confidence = 0.85
	}

	addr := bitsToUint(bits[:8])
	data := bitsToUint(bits[8:12])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:12],
		Payload: map[string]any{
			"address": addr,
			"data":    data,
			"te_us":   te,
		},
	}, nil
}
