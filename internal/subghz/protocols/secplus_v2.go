// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Security+ 2.0 (Chamberlain / LiftMaster / Craftsman myQ)
//
// Modulation : OOK, multi-width encoding (trinary/base-3)
// Bit rate   : ~2000 bps (TE ≈ 250 µs)
// Payload    : First packet — 20 trits (base-3 encoded)
// Preamble   : 10 short alternating pulses (~TE each)
// Sync       : long mark ≥4×TE (~1250 µs)
// Trit widths (space after ~1×TE mark):
//   Trit 0 : ~1.5×TE space  (~375 µs)
//   Trit 1 : ~2.5×TE space  (~625 µs)
//   Trit 2 : ~3.5×TE space  (~875 µs)
// Frequency  : 310 MHz, 315 MHz, 390 MHz (US market)
// Vendor     : Chamberlain Group (LiftMaster, Craftsman, myQ)
//
// NOTE: Full Security+ v2 decoding requires two packets and a de-interleave
// step. This decoder extracts the first packet's 20 trits and surfaces them
// for analysis. rolling_code and fixed_code are derived from lower and upper
// trit groups respectively.
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/secplus_v2.c
//   - jishminky/secplus Security+ v2 protocol documentation
//   - rtl_433 src/devices/secplus.c

package protocols

import "fmt"

// SecplusV2 decodes the first packet of a Security+ 2.0 trinary frame.
type SecplusV2 struct{}

func (p SecplusV2) Name() string     { return "Security+ v2" }
func (p SecplusV2) BitRate() float64 { return 2000.0 }

// Decode attempts to decode the first packet of a Security+ v2 frame.
//
// After the preamble, a long sync mark (≥4×TE) precedes 20 mark+space trit
// pairs. The space width determines the trit value: ~1.5×TE=0, ~2.5×TE=1,
// ~3.5×TE=2. A tolerance of 35% is used to keep adjacent trit widths distinct
// (adjacent widths differ by TE, which is ~40% of the smaller width).
func (p SecplusV2) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 100, 600)
	if !ok {
		return Result{}, fmt.Errorf("secplus_v2: cannot estimate TE")
	}

	// Find sync: a mark that is ≥4×TE (long mark after preamble).
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		if mark > 0 && abs32(mark) >= 4*te {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("secplus_v2: sync not found")
	}

	// Decode 20 trits: each trit = ~1×TE mark + variable space.
	// Space ~1.5×TE (±35%) → trit 0
	// Space ~2.5×TE (±35%) → trit 1
	// Space ~3.5×TE (±35%) → trit 2
	// 35% keeps adjacent width ranges non-overlapping (adjacent widths differ
	// by exactly 1×TE ≈ 40% of the smaller width).
	const tritTol = 35.0
	trits := make([]int, 0, 20)
	i := start
	matched := 0
decode:
	for len(trits) < 20 && i+1 < len(pulses) {
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
		switch {
		case nearRatio(sp, 3*te/2, tritTol):
			trits = append(trits, 0)
			matched++
		case nearRatio(sp, 5*te/2, tritTol):
			trits = append(trits, 1)
			matched++
		case nearRatio(sp, 7*te/2, tritTol):
			trits = append(trits, 2)
			matched++
		default:
			break decode
		}
		i += 2
	}

	if len(trits) < 20 {
		return Result{}, fmt.Errorf("secplus_v2: only %d trits decoded", len(trits))
	}
	confidence := float64(matched) / 20.0

	// Convert 20 trits (base-3, MSB first) to a uint64.
	var tritValue uint64
	for _, trit := range trits[:20] {
		tritValue = tritValue*3 + uint64(trit)
	}

	// Lower 10 trits → rolling code region; upper 10 trits → fixed code region.
	var rollingRaw uint64
	for _, trit := range trits[:10] {
		rollingRaw = rollingRaw*3 + uint64(trit)
	}
	var fixedRaw uint64
	for _, trit := range trits[10:20] {
		fixedRaw = fixedRaw*3 + uint64(trit)
	}

	// Represent as bytes for the Result.Bits field (one byte per trit).
	tritBytes := make([]byte, 20)
	for j, trit := range trits[:20] {
		tritBytes[j] = byte(trit)
	}

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       tritBytes,
		Payload: map[string]any{
			"trit_value":   tritValue,
			"rolling_code": uint32(rollingRaw),
			"fixed_code":   uint32(fixedRaw),
			"te_us":        te,
			"packet_type":  "first",
		},
	}, nil
}
