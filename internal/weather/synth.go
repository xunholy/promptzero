// SPDX-License-Identifier: AGPL-3.0-or-later

package weather

import (
	"fmt"
	"math"
	"strings"
)

// SynthInput describes a weather-station reading to encode into a 5-byte
// (40-bit) sensor frame — the inverse of DecodeBytes. Protocol selects the
// family ("Acurite-609TXC" or "LaCrosse-TX141TH-Bv2"); Channel/TestButton
// apply to LaCrosse only.
type SynthInput struct {
	Protocol     string  `json:"protocol"`
	SensorID     int     `json:"sensor_id"` // 0-255
	TemperatureC float64 `json:"temperature_c"`
	Humidity     int     `json:"humidity_percent"` // 0-100
	BatteryLow   bool    `json:"battery_low"`
	Channel      int     `json:"channel"`     // LaCrosse only, 0-3
	TestButton   bool    `json:"test_button"` // LaCrosse only
}

// Synth builds the 5-byte weather-station frame for the given reading, with
// the family's exact field packing and checksum, so DecodeBytes recovers
// the same reading (round-trip inverse).
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of DecodeBytes. The two covered families are
// public, long-stable rtl_433 layouts with deterministic checksums; the
// encoder reuses the package's own checksum/LFSR functions, so the
// generated frame is provably the one the decoder accepts. Generation only:
// it produces the bytes behind a 433 MHz weather-sensor spoof payload and
// transmits nothing (pair with an OOK TX stage), so it is Low risk like the
// decoder. Correctness is verifiable two ways: round-trip against
// DecodeBytes and hand-computed checksums.
func Synth(in SynthInput) ([]byte, error) {
	if in.SensorID < 0 || in.SensorID > 255 {
		return nil, fmt.Errorf("weather: sensor_id %d out of range (0-255)", in.SensorID)
	}
	if in.Humidity < 0 || in.Humidity > 100 {
		return nil, fmt.Errorf("weather: humidity %d out of range (0-100)", in.Humidity)
	}
	b := make([]byte, 5)
	b[0] = byte(in.SensorID)
	b[3] = byte(in.Humidity)

	switch normalizeProto(in.Protocol) {
	case "acurite":
		// 12-bit two's-complement Celsius ×10, top nibble in b[1], low byte
		// in b[2]; b[1] bit7 = battery-low. 8-bit sum checksum over 0-3.
		t10 := int(math.Round(in.TemperatureC * 10))
		if t10 < -2048 || t10 > 2047 {
			return nil, fmt.Errorf("weather: temperature %.1f°C out of Acurite range (12-bit ×0.1: -204.8..204.7)", in.TemperatureC)
		}
		t12 := uint16(t10) & 0x0fff
		b[1] = byte((t12 >> 8) & 0x0f)
		if in.BatteryLow {
			b[1] |= 0x80
		}
		b[2] = byte(t12 & 0xff)
		b[4] = (b[0] + b[1] + b[2] + b[3]) & 0xff
		return b, nil

	case "lacrosse":
		if in.Channel < 0 || in.Channel > 3 {
			return nil, fmt.Errorf("weather: channel %d out of range (LaCrosse: 0-3)", in.Channel)
		}
		// 12-bit raw = (tempC*10)+500, top nibble in b[1] low nibble, low
		// byte in b[2]; b[1]: bit7 battery, bit6 test, bits5-4 channel.
		raw := int(math.Round(in.TemperatureC*10)) + 500
		if raw < 0 || raw > 4095 {
			return nil, fmt.Errorf("weather: temperature %.1f°C out of LaCrosse range (raw 0-4095: -50.0..359.5)", in.TemperatureC)
		}
		b[1] = byte((raw >> 8) & 0x0f)
		b[1] |= byte((in.Channel & 0x03) << 4)
		if in.TestButton {
			b[1] |= 0x40
		}
		if in.BatteryLow {
			b[1] |= 0x80
		}
		b[2] = byte(raw & 0xff)
		b[4] = lfsrDigest8Reflect(b[:4], 0x31, 0xf4)
		return b, nil

	default:
		return nil, fmt.Errorf("weather: unsupported protocol %q (supported: Acurite-609TXC, LaCrosse-TX141TH-Bv2)", in.Protocol)
	}
}

// normalizeProto maps the accepted protocol spellings to a family key.
func normalizeProto(p string) string {
	switch s := strings.ToLower(strings.TrimSpace(p)); {
	case strings.Contains(s, "acurite") || strings.Contains(s, "609"):
		return "acurite"
	case strings.Contains(s, "lacrosse") || strings.Contains(s, "tx141"):
		return "lacrosse"
	default:
		return s
	}
}
