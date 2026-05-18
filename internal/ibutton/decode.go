// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ibutton decodes Dallas 1-Wire ROM IDs (a.k.a. iButton
// keys) into a structured view: family code → device-type name,
// 48-bit serial, and Dallas CRC-8 validation.
//
// # Wrap-vs-native judgement
//
// Native. The 1-Wire ROM ID layout is a 64-bit fixed structure
// published by Maxim/Dallas Semiconductor (Application Note 001)
// and the Dallas CRC-8 polynomial (0x31 reflected) is a few
// lines of bit-twiddling. The family-code → device-type
// mapping is a static lookup table (~50 entries from the
// public Maxim AN155 / AN1796 series). No vendor SDK, no
// hardware dependency, no protocol negotiation: pasting the
// hex bytes printed by a Flipper iButton dump is enough.
//
// # What this package covers
//
//   - Dallas DS1990A / DS2401 / DS2411 (the canonical
//     "unique ID" iButton — family 0x01) — by far the most
//     common form-factor encountered on intercoms and
//     building-access systems.
//   - The full Maxim 1-Wire device family (DS18B20
//     temperature sensors, DS2431 EEPROM, DS2438 battery
//     monitor, DS2408 8-channel switch, etc. — anything
//     that addresses on a Dallas 1-Wire bus shares the same
//     ROM-ID layout).
//   - Dallas CRC-8 (poly 0x31, init 0x00, reflected,
//     no final XOR) — verifies that the 8 bytes are a
//     well-formed ROM ID rather than a misread frame.
//
// # What this package does NOT cover (deliberately out of scope)
//
//   - Cyfral / Metakom / DS1996-style memory dumps — those are
//     separate Russian intercom-key protocols with their own
//     bit-layouts and Manchester encodings; future iterations
//     can add `ibutton_cyfral_decode` / `ibutton_metakom_decode`
//     in this package.
//   - Memory-contents decoding for the DS197x / DS24xx EEPROM
//     and battery-monitor families — only the ROM ID is decoded
//     here; per-device memory pages need device-specific parsers.
//   - Reading from a live 1-Wire bus — host-side decode only;
//     hardware ops live in internal/flipper (ibutton_read /
//     emulate / write).
package ibutton

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// Dallas is the decoded view of a Dallas 1-Wire ROM ID.
//
// Field layout matches the on-wire ROM ID transmission order
// (LSByte first on the bus, but rendered here in the
// natural left-to-right byte order from the hex input):
//
//	FamilyHex    : 8-bit family code (byte 0)
//	FamilyName   : device-type name from the family-code table
//	SerialHex    : 48-bit serial (bytes 1..6, big-endian)
//	CRC          : 8-bit CRC byte as captured (byte 7)
//	CRCExpected  : 8-bit CRC computed over bytes 0..6
//	CRCValid     : CRC == CRCExpected
type Dallas struct {
	ROMHex      string `json:"rom_hex"`
	FamilyCode  byte   `json:"family_code"`
	FamilyHex   string `json:"family_hex"`
	FamilyName  string `json:"family_name"`
	SerialHex   string `json:"serial_hex"`
	CRC         byte   `json:"crc"`
	CRCExpected byte   `json:"crc_expected"`
	CRCValid    bool   `json:"crc_valid"`
}

// Decode parses a hex-encoded Dallas 1-Wire ROM ID into a
// structured Dallas view. Accepts ':', '-', '_', whitespace as
// separators and a leading '0x' prefix.
//
// The input must decode to exactly 8 bytes (the fixed ROM-ID
// width). Shorter / longer inputs are rejected with a clear
// error — Cyfral and Metakom keys have different widths and
// require different decoders.
func Decode(hexBlob string) (*Dallas, error) {
	b, err := parseHex(hexBlob)
	if err != nil {
		return nil, err
	}
	return DecodeBytes(b)
}

// DecodeBytes parses a raw 8-byte ROM ID. Exposed so that
// callers already holding the bytes (e.g. another decoder
// stage) don't have to round-trip through hex encoding.
func DecodeBytes(b []byte) (*Dallas, error) {
	if len(b) != 8 {
		return nil, fmt.Errorf(
			"ibutton: Dallas 1-Wire ROM ID must be exactly 8 bytes; got %d (Cyfral and Metakom keys use different widths and need a dedicated decoder)",
			len(b))
	}
	d := &Dallas{
		ROMHex:      strings.ToUpper(hex.EncodeToString(b)),
		FamilyCode:  b[0],
		FamilyHex:   fmt.Sprintf("0x%02X", b[0]),
		FamilyName:  familyName(b[0]),
		SerialHex:   strings.ToUpper(hex.EncodeToString(b[1:7])),
		CRC:         b[7],
		CRCExpected: computeCRC(b[:7]),
	}
	d.CRCValid = d.CRC == d.CRCExpected
	return d, nil
}

// computeCRC is the Dallas/Maxim 1-Wire CRC-8 used to
// validate the ROM ID. Polynomial 0x31 (x^8 + x^5 + x^4 + 1),
// init 0x00, reflected, no final XOR. See Maxim AN-27.
//
// Implemented as a byte-at-a-time bit walker — the table-
// driven variant is faster but unnecessary for 7 bytes of
// input and obscures the polynomial.
func computeCRC(data []byte) byte {
	var crc byte
	for _, b := range data {
		crc ^= b
		for i := 0; i < 8; i++ {
			if crc&0x01 != 0 {
				crc = (crc >> 1) ^ 0x8C // 0x8C = reflect(0x31)
			} else {
				crc >>= 1
			}
		}
	}
	return crc
}

// familyName maps a Dallas 1-Wire family code to its
// canonical device-type name. Source: Maxim AN155 / AN1796 +
// the published Dallas product line. The table covers ~50
// devices — enough that any operator who pastes a real ROM
// ID will get a name back instead of "unknown".
//
// Codes not in the table return "Unknown family" so the
// caller can still surface the raw byte.
func familyName(code byte) string {
	if name, ok := dallasFamilyTable[code]; ok {
		return name
	}
	return fmt.Sprintf("Unknown family (0x%02X)", code)
}

var dallasFamilyTable = map[byte]string{
	0x01: "DS1990A / DS2401 / DS2411 — Unique 64-bit ID iButton",
	0x02: "DS1991 — Multi-key 1152-bit secure memory",
	0x04: "DS1994 / DS2404 — 4Kb NV memory + clock",
	0x05: "DS2405 — Single addressable switch",
	0x06: "DS1993 — 4Kb NV memory iButton",
	0x08: "DS1992 — 1Kb NV memory iButton",
	0x09: "DS1982 / DS2502 — 1Kb add-only memory",
	0x0A: "DS1995 — 16Kb NV memory iButton",
	0x0B: "DS1985 / DS2505 — 16Kb add-only memory",
	0x0C: "DS1996 — 64Kb NV memory iButton",
	0x0F: "DS1986 / DS2506 — 64Kb add-only memory",
	0x10: "DS1820 / DS18S20 / DS1920 — Temperature sensor",
	0x12: "DS2406 / DS2407 — Dual addressable switch + 1Kb memory",
	0x14: "DS1971 / DS2430A — 256-bit EEPROM + 64-bit OTP",
	0x16: "DS1954 — Java-powered cryptographic iButton",
	0x18: "DS1963S — SHA-1 iButton",
	0x1A: "DS1963L — Monetary iButton (256-byte NV memory)",
	0x1B: "DS2436 — Battery ID + monitor",
	0x1C: "DS28E04-100 — Dual-channel addressable switch + 4Kb",
	0x1D: "DS2423 — 4Kb NV memory + dual counter",
	0x1E: "DS2437 — Smart battery monitor",
	0x1F: "DS2409 — MicroLAN coupler",
	0x20: "DS2450 — 4-channel A/D converter",
	0x21: "DS1921 — Thermochron iButton (temperature logger)",
	0x22: "DS1822 — Econo temperature sensor",
	0x23: "DS1973 / DS2433 — 4Kb EEPROM",
	0x24: "DS1904 / DS2415 — RTC iButton",
	0x26: "DS2438 — Smart battery monitor + ADC + temperature",
	0x27: "DS2417 — RTC with interrupt",
	0x28: "DS18B20 — Programmable resolution temperature sensor",
	0x29: "DS2408 — 8-channel addressable switch",
	0x2C: "DS2890 — Single channel digital potentiometer",
	0x2D: "DS1972 / DS2431 — 1Kb EEPROM",
	0x30: "DS2760 / DS2761 / DS2762 — Battery monitor",
	0x33: "DS1961S / DS2432 — 1Kb EEPROM + SHA-1",
	0x37: "DS1977 — Password-secured 32Kb EEPROM",
	0x3A: "DS2413 — Dual-channel addressable switch (PIO)",
	0x3B: "DS1825 / MAX31826 — Multi-drop temperature sensor",
	0x41: "DS1922L / DS1922T / DS1923 / DS2422 — Thermochron with humidity",
	0x42: "DS28EA00 — Temperature sensor with chain function",
	0x43: "DS28EC20 — 20Kb EEPROM",
	0x44: "DS28E10 — Single-contact authenticator",
	0x51: "DS2751 — Multichemistry battery fuel gauge",
}

// parseHex strips separators and decodes a hex blob into bytes.
// Tolerates ':', '-', '_', whitespace, and a leading '0x'
// prefix — matches the convention used by every other native
// decoder in this codebase.
func parseHex(s string) ([]byte, error) {
	s = stripSeparators(s)
	if s == "" {
		return nil, fmt.Errorf("ibutton: empty hex input")
	}
	if strings.HasPrefix(strings.ToLower(s), "0x") {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ibutton: invalid hex: %w", err)
	}
	return b, nil
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case ':', '-', '_', ' ', '\t', '\n', '\r':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
