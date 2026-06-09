// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Intertechno V3 (433 MHz home-automation switches / dimmers)
//
// Wrap-vs-native: native. Ported faithfully from the Flipper firmware decoder;
// no third-party dependency, no shell-out. Decode-only (passive identification).
//
// Intertechno V3 is one of the most widely deployed 433.92 MHz home-automation
// remote protocols (Intertechno / CoCo / Elro / KlikAanKlikUit-compatible
// switches, sockets, and dimmers). OOK with a distinctive four-phase per-bit
// encoding (each bit is two mark/space pairs), which makes it cleanly
// distinguishable from the simple-PWM gate/garage protocols.
//
// Modulation : OOK, four-phase per-bit
// Timing     : te_short 275 µs (T), te_long 1375 µs (= 5T), te_delta 150 µs
// Start bit  : mark T + space 10T (~2750 µs) — the sync anchor
// Data bit   : two mark/space pairs; the FIRST space selects the value:
//                '1' = (T, 5T, T, T)  → first space 5T
//                '0' = (T, T,  T, 5T) → first space T
//              (the 36-bit "dimming" frame carries a dimm bit encoded (T,T,T,T),
//               which decodes as 0 here.)
// Stop bit   : mark T + space 38T (~10450 µs); a space ≥ 11T ends the frame.
// Payload    : 32-bit (standard) or 36-bit (dimming), MSB-first.
//   32-bit:  serial = code>>6 (26-bit) · all_ch = (code>>5)&1 ·
//            on/off = (code>>4)&1 · channel = ~code & 0xF (when not all_ch)
//   36-bit:  serial = code>>10 (26-bit) · all_ch = (code>>9)&1 ·
//            dimm_level = code & 0xF · channel = ~(code>>4) & 0xF (when not all_ch)
// Frequency  : 433.92 MHz
//
// References:
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/intertechno_v3.c
//     (te_short=275, te_long=1375, te_delta=150, min_count_bit_for_found=32,
//     INTERTECHNO_V3_DIMMING_COUNT_BIT=36; the feed() state machine — start
//     sync, four-phase per-bit reading, ≥11T stop — and check_remote_controller
//     field split, including the worked examples Key:0x3F86C59F (32-bit) and
//     Key:0x42D2E8856 (36-bit) used here as decode anchors). No checksum, so a
//     frame is gated by the distinctive start sync, the four-phase timing and
//     the exact 32/36-bit count.

package protocols

import "fmt"

// IntertechnoV3 decodes Intertechno V3 32/36-bit four-phase OOK frames.
type IntertechnoV3 struct{}

func (p IntertechnoV3) Name() string     { return "Intertechno V3" }
func (p IntertechnoV3) BitRate() float64 { return 333.0 } // ~1 bit per 4 phases (~3 ms)

// Decode attempts to decode an Intertechno V3 frame. It syncs on the start bit
// (mark T + space 10T), reads four-phase data bits (the first space of each bit
// selects the value: 5T → 1, T → 0), and stops on a ≥ 11T space.
func (p IntertechnoV3) Decode(pulses []int) (Result, error) {
	const teShort, teLong, delta = 275, 1375, 160
	const startSpace = 10 * teShort // ~2750 µs
	const stopSpace = 11 * teShort  // ≥ this ends the frame

	// Sync on the start bit: a ~T mark followed by a ~10T space (distinctive —
	// no data-bit space is that long, and it is below the stop threshold).
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		if pulses[i] > 0 && abs32(pulses[i]-teShort) <= delta &&
			pulses[i+1] < 0 && abs32(abs32(pulses[i+1])-startSpace) <= 4*delta {
			start = i + 2
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("intertechno_v3: start sync (mark + 10T space) not found")
	}

	bits := make([]byte, 0, 36)
	matched := 0
	i := start
	for len(bits) < 36 && i+1 < len(pulses) {
		m1, s1 := pulses[i], pulses[i+1]
		if m1 <= 0 || s1 >= 0 {
			break
		}
		// A long leading space is the stop/inter-frame gap — end the frame.
		if abs32(s1) >= stopSpace {
			break
		}
		// A data bit consumes four phases: mark, space1, mark, space2.
		if i+3 >= len(pulses) || pulses[i+2] <= 0 || pulses[i+3] >= 0 {
			break
		}
		sp1 := abs32(s1)
		switch {
		case abs32(sp1-teLong) <= 4*delta:
			bits = append(bits, 1)
			matched++
		case abs32(sp1-teShort) <= delta:
			bits = append(bits, 0)
			matched++
		default:
			i = len(pulses)
			continue
		}
		i += 4
	}
	if len(bits) != 32 && len(bits) != 36 {
		return Result{}, fmt.Errorf("intertechno_v3: decoded %d bits; expected 32 or 36", len(bits))
	}

	var data uint64
	for _, b := range bits {
		data = data<<1 | uint64(b)
	}

	res := &Result{
		Protocol:   p.Name(),
		Confidence: float64(matched) / float64(len(bits)),
		Bits:       bits,
		Payload:    map[string]any{"code": data, "bits": len(bits), "te_us": teShort},
	}
	if len(bits) == 32 {
		res.Payload["serial"] = (data >> 6) & 0x3FFFFFF
		allCh := (data >> 5) & 0x1
		res.Payload["all_channels"] = allCh == 1
		res.Payload["on"] = (data>>4)&0x1 == 1
		if allCh == 1 {
			res.Payload["channel"] = "all"
		} else {
			res.Payload["channel"] = (^data) & 0xF
		}
	} else { // 36-bit dimming frame
		res.Payload["serial"] = (data >> 10) & 0x3FFFFFF
		allCh := (data >> 9) & 0x1
		res.Payload["all_channels"] = allCh == 1
		res.Payload["dimm_level"] = data & 0xF
		if allCh == 1 {
			res.Payload["channel"] = "all"
		} else {
			res.Payload["channel"] = (^(data >> 4)) & 0xF
		}
	}
	return *res, nil
}
