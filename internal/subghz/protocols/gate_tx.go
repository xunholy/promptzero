// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Gate TX (GateTX)
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : ~950 bps (te_short 350 µs, te_long 700 µs)
// Payload    : 24-bit code -> 20-bit serial + 4-bit button (from the reversed key)
// Header     : ~47×te_short space (~16.4 ms) then a te_long start-bit mark
// Bit "0"    : te_short space + te_long mark   (350 + 700 µs)
// Bit "1"    : te_long space + te_short mark   (700 + 350 µs)
// Frequency  : 433.92 MHz
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/gate_tx.c
//     (te_short=350, te_long=700, te_delta=100, min_count_bit=24; the encoder
//     get_upload and decoder feed loops + the serial/btn extraction)

package protocols

import "fmt"

// GateTX decodes Gate TX 24-bit fixed-code OOK/PWM frames.
type GateTX struct{}

func (p GateTX) Name() string     { return "Gate TX" }
func (p GateTX) BitRate() float64 { return 950.0 }

// Decode attempts to decode a Gate TX frame from the pulse sequence.
//
// The frame is a long header space (~47×TE) + a te_long start-bit mark, then 24
// MSB-first PWM bits where each bit is a space followed by a mark: bit 0 =
// short space + long mark, bit 1 = long space + short mark. The 24-bit code is
// bit-reversed and split into a 20-bit serial and a 4-bit button per the Flipper
// reference.
func (p GateTX) Decode(pulses []int) (Result, error) {
	// TE is the SHORT element; both 1×TE and 2×TE appear ~equally per bit (plus
	// the 2×TE start bit), so estimateTEMin (smallest recurring bucket) is the
	// correct estimator here — estimateTE would mis-pick 2×TE.
	te, ok := estimateTEMin(pulses, 200, 900)
	if !ok {
		return Result{}, fmt.Errorf("gate_tx: cannot estimate TE")
	}

	// Sync: a long header space (≥30×TE) immediately followed by a te_long
	// (≈2×TE) start-bit mark.
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		sp := pulses[i]
		mk := pulses[i+1]
		if sp < 0 && abs32(sp) >= 30*te && mk > 0 && nearRatio(mk, 2*te, 60) {
			start = i + 2
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("gate_tx: sync not found")
	}

	// Read 24 bits, each a (space, mark) pair.
	bits := make([]byte, 0, 24)
	matched := 0
	i := start
	for len(bits) < 24 && i+1 < len(pulses) {
		if pulses[i] >= 0 || pulses[i+1] <= 0 {
			break
		}
		sp := abs32(pulses[i])
		mk := pulses[i+1]
		switch {
		case nearRatio(sp, te, 60) && nearRatio(mk, 2*te, 60):
			bits = append(bits, 0)
			matched++
		case nearRatio(sp, 2*te, 60) && nearRatio(mk, te, 60):
			bits = append(bits, 1)
			matched++
		default:
			i = len(pulses) // stop
			continue
		}
		i += 2
	}
	if len(bits) < 24 {
		return Result{}, fmt.Errorf("gate_tx: only %d bits decoded", len(bits))
	}

	code := bitsToUint(bits[:24])
	rev := reverseBits(code, 24)
	serial := (rev&0xFF)<<12 | ((rev>>8)&0xFF)<<4 | ((rev >> 20) & 0x0F)
	btn := (rev >> 16) & 0x0F

	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 24.0,
		Bits:       bits[:24],
		Payload: map[string]any{
			"code":   code,
			"serial": serial,
			"button": btn,
			"te_us":  te,
		},
	}, nil
}

// reverseBits reverses the low n bits of v (MSB<->LSB).
func reverseBits(v uint32, n int) uint32 {
	var r uint32
	for i := 0; i < n; i++ {
		r = r<<1 | (v>>uint(i))&1
	}
	return r
}
