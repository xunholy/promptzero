// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Magicode
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~1000 bps (TE ≈ 300 µs)
// Payload    : 28-bit fixed code
// Sync       : 1×TE mark + 32×TE space
// Bit "1"    : 2×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 2×TE space
// Frequency  : 433.92 MHz
// Vendor     : Magicode (UK/EU)
//
// Magicode is a 28-bit fixed-code OOK protocol used in UK and European
// gate and door openers. The 28-bit payload contains a serial number
// and button identifier.
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/magicode.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/magicode.c

package protocols

import "fmt"

// Magicode decodes Magicode 28-bit OOK frames.
type Magicode struct{}

func (p Magicode) Name() string     { return "Magicode" }
func (p Magicode) BitRate() float64 { return 1000.0 }

// Decode attempts to decode a Magicode frame.
func (p Magicode) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 150, 800)
	if !ok {
		return Result{}, fmt.Errorf("magicode: cannot estimate TE")
	}

	// Sync: 1×TE mark + ≥25×TE space
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
		return Result{}, fmt.Errorf("magicode: sync not found")
	}

	// "1" = 2×TE mark + 1×TE space; "0" = 1×TE mark + 2×TE space
	bits := make([]byte, 0, 28)
	i := start
	matched := 0
	for len(bits) < 28 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		sp := abs32(space)
		if nearRatio(mark, 2*te, 60) && nearRatio(sp, te, 60) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(mark, te, 60) && nearRatio(sp, 2*te, 60) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 28 {
		return Result{}, fmt.Errorf("magicode: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 28.0
	code := bitsToUint32(bits[:28])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:28],
		Payload: map[string]any{
			"code":  code,
			"te_us": te,
		},
	}, nil
}
