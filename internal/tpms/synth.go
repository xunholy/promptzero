// SPDX-License-Identifier: AGPL-3.0-or-later

package tpms

import (
	"fmt"
	"strings"
)

// SynthInput describes a TPMS frame to generate: a 32-bit sensor ID, any
// data bytes that follow it (pressure / temperature / status — left to the
// caller, since their layout is per-model and unverifiable here, exactly as
// Decode declines to interpret them), the CRC-8 polynomial to seal it with,
// and the Manchester line convention.
type SynthInput struct {
	SensorID uint32 `json:"sensor_id"`
	Payload  []byte `json:"payload,omitempty"` // data bytes after the 4-byte ID, before the CRC
	CRCPoly  byte   `json:"crc_poly"`          // 0x07 / 0x2F / 0x13; 0 → default 0x07
	GEThomas bool   `json:"ge_thomas"`         // false = IEEE 802.3 (default), true = G.E. Thomas
}

// maxSynthPayload bounds the optional data field so a synthesized frame
// stays in the size range of real TPMS sensors (4-byte ID + ≤12 data + CRC).
const maxSynthPayload = 12

// Synth builds the Manchester bit-stream for a TPMS frame — the inverse of
// Decode. It lays out [sensor ID:4][payload…][CRC-8], computes the CRC over
// everything before it, and Manchester-line-codes the result. Round-trip:
// Decode recovers the same 32-bit sensor ID, the same payload bytes as
// DecodedHex, and lists the chosen polynomial in CRC8Matches.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the existing Decode. TPMS framing is a public,
// deterministic transform (the same rtl_433-derived Manchester + CRC-8
// families Decode covers); generation is pure bit + CRC maths, no crypto,
// no state, no hardware. It produces the bits behind a TPMS-spoof payload —
// it does NOT transmit (pair with a Sub-GHz TX stage), so it carries the
// same Low risk as Decode. Correctness is verifiable two ways: round-trip
// against Decode, and hand-computed CRC over a known payload.
//
// Per-model pressure/temperature field interpretation is deliberately NOT
// imposed — the caller supplies the data bytes verbatim, mirroring Decode's
// refusal to guess scaling it cannot verify (a confidently-wrong reading is
// worse than none).
func Synth(in SynthInput) (string, error) {
	poly := in.CRCPoly
	if poly == 0 {
		poly = 0x07
	}
	known := false
	for _, p := range crc8Polys {
		if p.poly == poly {
			known = true
			break
		}
	}
	if !known {
		return "", fmt.Errorf("tpms: unsupported CRC-8 polynomial 0x%02X (covered: 0x07, 0x2F, 0x13)", poly)
	}
	if len(in.Payload) > maxSynthPayload {
		return "", fmt.Errorf("tpms: payload is %d bytes; max %d (4-byte sensor ID + payload + CRC)", len(in.Payload), maxSynthPayload)
	}

	data := []byte{
		byte(in.SensorID >> 24), byte(in.SensorID >> 16), byte(in.SensorID >> 8), byte(in.SensorID),
	}
	data = append(data, in.Payload...)
	frame := append(append([]byte{}, data...), crc8(data, poly))
	return encodeManchester(frame, !in.GEThomas), nil
}

// encodeManchester encodes payload bytes (MSB-first) to a '0'/'1' bit
// string under the IEEE 802.3 convention (data 0 = "10", data 1 = "01")
// or G.E. Thomas (the inverse). It is the inverse of the decoder's line
// stage, so a round trip verifies the decode path without a real capture.
func encodeManchester(payload []byte, ieee bool) string {
	var sb strings.Builder
	sb.Grow(len(payload) * 16)
	for _, b := range payload {
		for j := 7; j >= 0; j-- {
			bit := (b >> uint(j)) & 1
			switch {
			case bit == 0 && ieee:
				sb.WriteString("10")
			case bit == 0 && !ieee:
				sb.WriteString("01")
			case bit == 1 && ieee:
				sb.WriteString("01")
			default: // bit == 1 && !ieee
				sb.WriteString("10")
			}
		}
	}
	return sb.String()
}
