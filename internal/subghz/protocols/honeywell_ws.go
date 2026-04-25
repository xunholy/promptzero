// SPDX-License-Identifier: AGPL-3.0-or-later

// Protocol: Honeywell WS (5800 series wireless sensors)
//
// Modulation : ASK (OOK variant), Pulse Width Modulation
// Bit rate   : ~3000 bps (TE ≈ 170 µs)
// Payload    : 48 bits total
//              bits 0..23  — 24-bit serial number
//              bits 24..27 — loop/zone bits (4 bits)
//              bits 28..31 — status/tamper bits (4 bits)
//              bits 32..47 — 16-bit checksum / CRC
// Preamble   : several short alternating pulses
// Sync       : long mark (≥10×TE)
// Bit "1"    : 2×TE mark + 1×TE space
// Bit "0"    : 1×TE mark + 2×TE space
// Frequency  : 345 MHz (US)
// Vendor     : Honeywell / Resideo (formerly ADT compatible sensors)
//
// References:
//   - rtl_433 src/devices/honeywell.c
//   - Honeywell 5800 series compatibility notes
//   - flipperdevices/flipperzero-firmware lib/subghz/protocols/honeywell_wdb.c

package protocols

import "fmt"

// HoneywellWS decodes Honeywell 5800-series wireless sensor frames.
type HoneywellWS struct{}

func (p HoneywellWS) Name() string      { return "Honeywell WS" }
func (p HoneywellWS) BitRate() float64  { return 3000.0 }

// Decode attempts to decode a Honeywell WS frame.
func (p HoneywellWS) Decode(pulses []int) (Result, error) {
	te, ok := estimateTE(pulses, 80, 400)
	if !ok {
		return Result{}, fmt.Errorf("honeywell_ws: cannot estimate TE")
	}

	// Sync: long mark ≥8×TE
	start := -1
	for i := 0; i+1 < len(pulses); i++ {
		mark := pulses[i]
		space := pulses[i+1]
		if mark > 0 && abs32(mark) >= 8*te && space < 0 {
			start = i + 1
			break
		}
	}
	if start < 0 {
		return Result{}, fmt.Errorf("honeywell_ws: sync not found")
	}

	// "1" = 2×TE mark + 1×TE space; "0" = 1×TE mark + 2×TE space
	bits := make([]byte, 0, 48)
	i := start
	matched := 0
	for len(bits) < 48 && i+1 < len(pulses) {
		mark := pulses[i]
		space := pulses[i+1]
		if mark <= 0 {
			i++
			continue
		}
		sp := abs32(space)
		if nearRatio(mark, 2*te, 70) && nearRatio(sp, te, 70) {
			bits = append(bits, 1)
			matched++
		} else if nearRatio(mark, te, 70) && nearRatio(sp, 2*te, 70) {
			bits = append(bits, 0)
			matched++
		} else {
			break
		}
		i += 2
	}

	if len(bits) < 32 {
		return Result{}, fmt.Errorf("honeywell_ws: only %d bits decoded", len(bits))
	}
	confidence := float64(matched) / 48.0

	serial := bitsToUint32(bits[:24])
	loop := bitsToUint(bits[24:28])
	status := bitsToUint(bits[28:32])

	payload := map[string]any{
		"serial": serial,
		"loop":   loop,
		"status": status,
		"te_us":  te,
	}
	if len(bits) >= 48 {
		crc := bitsToUint(bits[32:48])
		payload["checksum"] = crc
	}

	return Result{
		Protocol:   p.Name(),
		Confidence: confidence,
		Bits:       bits,
		Payload:    payload,
	}, nil
}
