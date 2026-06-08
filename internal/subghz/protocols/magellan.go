// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Magellan (security-system sensors / remotes)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware decoder;
// no third-party dependency, no shell-out. Decode-only (passive identification).
//
// Modulation : OOK, Pulse Width Modulation
// Bit rate   : te_short 200 µs, te_long 400 µs (2×TE)
// Payload    : 32-bit frame = 24-bit data + 8-bit CRC8. The 24-bit data, read
//              with its bit order reversed, splits into an 8-bit event code and
//              a 16-bit serial number.
// Bit "1"    : te_short mark + te_long space (200 + 400 µs)
// Bit "0"    : te_long mark + te_short space (400 + 200 µs)
// Header     : ~12×te_short preamble pulses, then a te_long×3 (1200 µs) start
//              mark + te_long space; a long (≥3×te_long) space ends the frame.
// CRC        : CRC-8 poly 0x31, init 0x00, over the three data bytes; must equal
//              the trailing byte — frames that fail are rejected (not surfaced).
// Frequency  : 433.92 MHz
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/magellan.c
//     (te_short=200, te_long=400, te_delta=100, min_count_bit=32; the feed()
//     state machine, get_upload() encoder, check_crc()/magellan_crc8() and
//     check_remote_controller() — serial = reverse(data>>8,24) & 0xFFFF,
//     event = (reverse(data>>8,24) >> 16) & 0xFF). The firmware's own worked
//     example: 0x37AE4828 -> CRC 0x28, reversed 0x1275EC -> event 0x12,
//     serial 0x75EC.

package protocols

import "fmt"

// Magellan decodes Magellan 32-bit security-sensor OOK/PWM frames.
type Magellan struct{}

func (p Magellan) Name() string     { return "Magellan" }
func (p Magellan) BitRate() float64 { return 5000.0 } // ~1 bit per 3×te_short

// magellanCRC8 is a verbatim port of subghz_protocol_magellan_crc8: CRC-8 with
// polynomial 0x31, initial value 0x00, MSB-first, no reflection or final XOR.
func magellanCRC8(data []byte) byte {
	var crc byte
	for _, b := range data {
		crc ^= b
		for j := 0; j < 8; j++ {
			if crc&0x80 != 0 {
				crc = (crc << 1) ^ 0x31
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// Decode attempts to decode a Magellan frame from the pulse sequence.
//
// It anchors on the distinctive start mark (te_long×3 ≈ 1200 µs, far longer than
// any data element) followed by a te_long space, then reads 32 MSB-first PWM
// bits (bit 1 = short mark + long space, bit 0 = long mark + short space). The
// trailing CRC-8 byte must validate, otherwise the frame is rejected.
func (p Magellan) Decode(pulses []int) (Result, error) {
	// te_short ≈ 200 µs; both te_short and te_long (2×TE) appear per bit, so the
	// smallest recurring bucket is the right TE estimate.
	te, ok := estimateTEMin(pulses, 100, 600)
	if !ok {
		return Result{}, fmt.Errorf("magellan: cannot estimate TE")
	}

	// Sync on the start bit: a ~6×TE (te_long×3) mark immediately followed by a
	// ~2×TE (te_long) space.
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		if pulses[i] > 0 && nearRatio(pulses[i], 6*te, 30) &&
			pulses[i+1] < 0 && nearRatio(abs32(pulses[i+1]), 2*te, 40) {
			start = i + 2
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("magellan: start bit not found")
	}

	// Read 32 bits, each a (mark, space) pair.
	bits := make([]byte, 0, 32)
	matched := 0
	i := start
	for len(bits) < 32 && i+1 < len(pulses) {
		if pulses[i] <= 0 || pulses[i+1] >= 0 {
			break
		}
		mark := pulses[i]
		space := abs32(pulses[i+1])
		switch {
		case nearRatio(mark, te, 50) && nearRatio(space, 2*te, 40):
			bits = append(bits, 1)
			matched++
		case nearRatio(mark, 2*te, 40) && nearRatio(space, te, 50):
			bits = append(bits, 0)
			matched++
		default:
			i = len(pulses) // unrecognised element — stop
			continue
		}
		i += 2
	}
	if len(bits) < 32 {
		return Result{}, fmt.Errorf("magellan: only %d bits decoded", len(bits))
	}

	data := bitsToUint(bits[:32])

	// CRC-8 gate: the low byte must match the CRC of the three data bytes.
	payload := []byte{byte(data >> 24), byte(data >> 16), byte(data >> 8)}
	if magellanCRC8(payload) != byte(data&0xFF) {
		return Result{}, fmt.Errorf("magellan: CRC mismatch")
	}

	// The 24-bit payload is bit-reversed before the field split.
	rev := reverseBits(data>>8, 24)
	serial := rev & 0xFFFF
	event := (rev >> 16) & 0xFF

	return Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / 32.0,
		Bits:       bits[:32],
		Payload: map[string]any{
			"code":   data,
			"serial": serial,
			"event":  event,
			"te_us":  te,
		},
	}, nil
}
