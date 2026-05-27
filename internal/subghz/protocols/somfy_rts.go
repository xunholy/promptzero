// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Somfy RTS
//
// Modulation : OOK, Manchester encoding
// Bit rate   : ~781 bps (TE ≈ 640 µs, symbol = 2×TE = 1280 µs)
// Payload    : 56 bits (7 bytes):
//
//	byte 0     : encryption key (8 bits)
//	byte 1 hi  : control command (4 bits) — 0x1=My, 0x2=Up, 0x4=Down, 0x8=Prog
//	byte 1 lo  : CRC (4 bits)
//	bytes 2-3  : rolling code (16 bits, big-endian)
//	bytes 4-6  : remote address (24 bits, big-endian)
//
// Hardware sync: 2 wake-up pulses (~9700 µs mark + gap), then soft sync:
//
//	≥3×TE mark + ≥3×TE space (~2560 µs mark + 2560 µs space)
//
// Manchester: rising edge (space→mark) = 1, falling edge (mark→space) = 0.
//
//	Each bit cell = 2 half-periods of TE.
//
// Frequency  : 433.42 MHz (EU)
// Vendor     : Somfy Group (France) — Telis 1/4 RTS, Situo 1/5 RTS
//
// Common in: European motorized blinds, shutters, awnings, screens.
// The payload bytes 1–6 are XOR-obfuscated with the key byte; this decoder
// surfaces the raw 56-bit Manchester payload without de-obfuscation.
//
// References:
//   - Somfy RTS protocol reverse-engineering: https://pushstack.wordpress.com/somfy-rts-protocol/
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/somfy_rts.c
//   - DarkFlippers/unleashed-firmware lib/subghz/protocols/somfy_rts.c

package protocols

import "fmt"

// SomfyRTS decodes Somfy RTS 56-bit Manchester-encoded OOK frames.
type SomfyRTS struct{}

func (p SomfyRTS) Name() string     { return "Somfy RTS" }
func (p SomfyRTS) BitRate() float64 { return 781.0 }

// Decode attempts to decode a Somfy RTS frame from the pulse sequence.
//
// After finding the soft sync (long mark + long space ≥3×TE each), the decoder
// walks 56 Manchester bit cells. Each cell consists of two half-periods of TE:
// a rising transition (space→mark) encodes 1, a falling transition
// (mark→space) encodes 0. The raw bits are returned without XOR
// de-obfuscation.
func (p SomfyRTS) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 300, 1500)
	if !ok {
		return Result{}, fmt.Errorf("somfy_rts: cannot estimate TE")
	}

	// Find soft sync: mark ≥3×TE followed by space ≥3×TE.
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && space < 0 {
			if abs32(mark) >= 3*te && abs32(space) >= 3*te {
				start = i + 2
				break
			}
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("somfy_rts: sync not found")
	}

	// Manchester decode: each bit cell is a pair of half-periods (each ≈TE).
	// The first half-period sets the polarity and the transition at the cell
	// midpoint determines the bit value:
	//   first half = space (negative), second half = mark (positive) → bit 1
	//   first half = mark  (positive), second half = space (negative) → bit 0
	const wantBits = 56
	bits := make([]byte, 0, wantBits)
	matched := 0
	i := start

	for len(bits) < wantBits && i+1 < len(pulses) {
		a := pulses[i]
		b := pulses[i+1]
		absA := abs32(a)
		absB := abs32(b)

		if !nearRatio(absA, te, 70) || !nearRatio(absB, te, 70) {
			// Try to handle split half-cells (two consecutive same-polarity
			// pulses each ≈TE can be merged into a double cell for the next
			// bit boundary), but for simplicity just stop if timing drifts.
			break
		}

		if a < 0 && b > 0 {
			// space → mark: rising transition = 1
			bits = append(bits, 1)
			matched++
		} else if a > 0 && b < 0 {
			// mark → space: falling transition = 0
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < wantBits {
		return Result{}, fmt.Errorf("somfy_rts: only %d bits decoded", len(bits))
	}

	confidence := float64(matched) / float64(wantBits)

	// Pack 56 bits into 7 bytes (MSB first within each byte).
	raw := make([]byte, 7)
	for idx := 0; idx < 7; idx++ {
		var byt byte
		for bit := 0; bit < 8; bit++ {
			byt = (byt << 1) | (bits[idx*8+bit] & 1)
		}
		raw[idx] = byt
	}

	key := raw[0]
	ctrl := (raw[1] >> 4) & 0x0F
	crc := raw[1] & 0x0F
	rollingCode := uint32(raw[2])<<8 | uint32(raw[3])
	address := uint32(raw[4])<<16 | uint32(raw[5])<<8 | uint32(raw[6])

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits[:wantBits],
		Payload: map[string]any{
			"key":          key,
			"ctrl":         ctrl,
			"crc":          crc,
			"rolling_code": rollingCode,
			"address":      address,
			"te_us":        te,
		},
	}, nil
}
