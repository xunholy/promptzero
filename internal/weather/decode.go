// SPDX-License-Identifier: AGPL-3.0-or-later

// Package weather decodes 433 MHz weather-station sensor frames (the
// LaCrosse / Acurite families the Flipper "Weather Station" FAP and
// rtl_433 cover) from a pre-demodulated 40-bit frame into the
// interpreted reading — sensor ID, temperature, humidity, battery —
// for the formats whose checksum validates.
//
// # Wrap-vs-native judgement
//
// Native. Like subghz_pocsag_decode and subghz_tpms_decode, the hard,
// reusable part is a public, deterministic transform: rtl_433's
// long-stable device layouts plus their exact checksum algorithms.
// Operators bring a pre-demodulated frame (rtl_433, a Flipper Sub-GHz
// FSK/OOK capture pre-extracted to bits, or Universal Radio Hacker)
// and decode offline — no RF at decode time.
//
// # Why the checksum is the principled gate
//
// The two families this package covers share an identical byte
// envelope — [id][flags+temp_hi][temp_lo][humidity][checksum] — and
// differ only in their temperature scaling and their checksum
// algorithm. A reading is therefore reported ONLY for a format whose
// checksum validates over the frame: the checksum disambiguates which
// family (and so which scaling) produced the bytes, exactly as the
// CRC-8 disambiguates the Manchester convention in subghz_tpms_decode.
// When no known checksum matches, the raw bytes are surfaced with a
// note rather than a guessed reading — a confidently-wrong temperature
// is worse than none for a security tool.
//
// # Covered formats
//
//   - Acurite 609TXC (5 bytes; 12-bit two's-complement temp ×10 °C;
//     8-bit sum checksum over bytes 0-3).
//   - LaCrosse TX141TH-Bv2 / TX141-Bv3 (5 bytes; (raw-500)×0.1 °C;
//     lfsr_digest8_reflect(gen 0x31, key 0xF4) over bytes 0-3, with a
//     channel + test-button flag).
//
// # Out of scope (deliberately)
//
//   - FSK/OOK and PWM/Manchester demodulation (bring a pre-demodulated
//     40-bit frame).
//   - Multi-frame Acurite 5n1 / Oregon Scientific v2.1/v3 families
//     (variable-length, Manchester, separate envelopes) — the two
//     fixed-40-bit families here are the common Flipper case and are
//     fully round-trip verifiable.
package weather

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"
)

// Reading is one weather-sensor format's interpretation of a frame,
// reported only when that format's checksum validates.
type Reading struct {
	Protocol     string   `json:"protocol"`
	SensorID     string   `json:"sensor_id"`
	SensorIDDec  int      `json:"sensor_id_decimal"`
	Channel      *int     `json:"channel,omitempty"`
	TemperatureC float64  `json:"temperature_c"`
	TemperatureF float64  `json:"temperature_f"`
	Humidity     int      `json:"humidity_percent"`
	BatteryLow   bool     `json:"battery_low"`
	TestButton   *bool    `json:"test_button,omitempty"`
	ChecksumKind string   `json:"checksum"`
	Notes        []string `json:"notes,omitempty"`
}

// Result is the structured decode of a weather-station frame.
type Result struct {
	InputBytes int       `json:"input_bytes"`
	RawHex     string    `json:"raw_hex"`
	Readings   []Reading `json:"readings"`
	Notes      []string  `json:"notes,omitempty"`
}

// DecodeBytes decodes a 5-byte (40-bit) weather frame supplied as
// bytes. It returns every covered format whose checksum validates.
func DecodeBytes(b []byte) (*Result, error) {
	if len(b) != 5 {
		return nil, fmt.Errorf("weather: frame is %d bytes; the covered LaCrosse/Acurite families are exactly 5 bytes (40 bits)", len(b))
	}
	r := &Result{
		InputBytes: len(b),
		RawHex:     strings.ToUpper(hex.EncodeToString(b)),
	}
	if rd, ok := decodeAcurite609(b); ok {
		r.Readings = append(r.Readings, rd)
	}
	if rd, ok := decodeLaCrosseTX141TH(b); ok {
		r.Readings = append(r.Readings, rd)
	}
	if len(r.Readings) == 0 {
		r.Notes = append(r.Notes,
			"no covered format's checksum validated over these bytes — the frame is from another family, a different bit alignment, or noise; raw bytes surfaced for manual rtl_433 model matching")
	}
	return r, nil
}

// DecodeHex parses a hex frame (':' '-' '_' / whitespace tolerated)
// and decodes it.
func DecodeHex(s string) (*Result, error) {
	clean := stripSeparators(s)
	if clean == "" {
		return nil, fmt.Errorf("weather: empty hex frame")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("weather: invalid hex frame: %w", err)
	}
	return DecodeBytes(b)
}

// DecodeBits parses a 40-character '0'/'1' bit-stream (separators
// tolerated) MSB-first into bytes and decodes it.
func DecodeBits(s string) (*Result, error) {
	clean := stripSeparators(s)
	if clean == "" {
		return nil, fmt.Errorf("weather: empty bit-stream")
	}
	if len(clean)%8 != 0 {
		return nil, fmt.Errorf("weather: bit-stream length %d is not a multiple of 8", len(clean))
	}
	b := make([]byte, len(clean)/8)
	for i := 0; i < len(clean); i++ {
		switch clean[i] {
		case '0':
		case '1':
			b[i/8] |= 1 << uint(7-i%8)
		default:
			return nil, fmt.Errorf("weather: non-binary character %q in bit-stream", string(clean[i]))
		}
	}
	return DecodeBytes(b)
}

// decodeAcurite609 decodes the Acurite 609TXC layout and reports a
// reading iff the 8-bit sum checksum validates. Layout per rtl_433
// src/devices/acurite.c (609TXC).
func decodeAcurite609(b []byte) (Reading, bool) {
	if (b[0]+b[1]+b[2]+b[3])&0xff != b[4] {
		return Reading{}, false
	}
	// 12-bit two's-complement Celsius ×10: sign bit at frame bit 11,
	// recovered by left-justifying into an int16 then arithmetic-
	// shifting back.
	raw := int16((uint16(b[1]&0x0f) << 12) | (uint16(b[2]) << 4))
	tempC := round1(float64(raw>>4) * 0.1)
	humidity := int(b[3])
	rd := Reading{
		Protocol:     "Acurite-609TXC",
		SensorID:     fmt.Sprintf("%02X", b[0]),
		SensorIDDec:  int(b[0]),
		TemperatureC: tempC,
		TemperatureF: cToF(tempC),
		Humidity:     humidity,
		BatteryLow:   b[1]&0x80 != 0,
		ChecksumKind: "8-bit sum over bytes 0-3",
	}
	if humidity > 100 {
		rd.Notes = append(rd.Notes, "humidity > 100% — checksum passed but reading is implausible; treat with suspicion")
	}
	return rd, true
}

// decodeLaCrosseTX141TH decodes the LaCrosse TX141TH-Bv2 / TX141-Bv3
// layout and reports a reading iff lfsr_digest8_reflect validates.
// Layout per rtl_433 src/devices/lacrosse_tx141x.c.
func decodeLaCrosseTX141TH(b []byte) (Reading, bool) {
	if lfsrDigest8Reflect(b[:4], 0x31, 0xf4) != b[4] {
		return Reading{}, false
	}
	raw := (int(b[1]&0x0f) << 8) | int(b[2])
	tempC := round1(float64(raw-500) * 0.1)
	humidity := int(b[3])
	channel := int(b[1]&0x30) >> 4
	test := b[1]&0x40 != 0
	rd := Reading{
		Protocol:     "LaCrosse-TX141TH-Bv2",
		SensorID:     fmt.Sprintf("%02X", b[0]),
		SensorIDDec:  int(b[0]),
		Channel:      &channel,
		TemperatureC: tempC,
		TemperatureF: cToF(tempC),
		Humidity:     humidity,
		BatteryLow:   b[1]&0x80 != 0,
		TestButton:   &test,
		ChecksumKind: "lfsr_digest8_reflect(gen 0x31, key 0xF4) over bytes 0-3",
	}
	if humidity > 100 {
		rd.Notes = append(rd.Notes, "humidity > 100% — checksum passed but reading is implausible; treat with suspicion")
	}
	return rd, true
}

// lfsrDigest8Reflect is the rtl_433 LFSR digest (reflected variant):
// bytes processed last-to-first, bits LSB-to-MSB, key left-shifted
// with polynomial feedback when its MSB is set. Mirrors
// src/bit_util.c::lfsr_digest8_reflect exactly.
func lfsrDigest8Reflect(message []byte, gen, key byte) byte {
	var sum byte
	for k := len(message) - 1; k >= 0; k-- {
		data := message[k]
		for i := 0; i < 8; i++ {
			if (data>>uint(i))&1 == 1 {
				sum ^= key
			}
			if key&0x80 != 0 {
				key = (key << 1) ^ gen
			} else {
				key <<= 1
			}
		}
	}
	return sum
}

func cToF(c float64) float64 { return round1(c*9.0/5.0 + 32.0) }

func round1(x float64) float64 { return math.Round(x*10) / 10 }

func stripSeparators(s string) string {
	var sb strings.Builder
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}
