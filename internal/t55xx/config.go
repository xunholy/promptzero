// SPDX-License-Identifier: AGPL-3.0-or-later

// Package t55xx decodes the T5577 / T55x7 (Atmel/Microchip ATA5577)
// configuration register — block 0 of page 0, the 32-bit word that controls
// how an LF 125 kHz tag modulates and clocks its data. The T5577 is the
// ubiquitous rewritable LF "blank" used to clone EM4100 / HID Prox / Indala /
// AWID credentials; reading its config block tells an operator the modulation
// scheme, data bit rate, block count, and protection flags a tag is set to —
// the diagnostic complement to the project's existing T5577 clone/write
// tooling (rfid_write / loader_t5577_multiwriter).
//
// Wrap-vs-native: native. The decode is a fixed set of bit-field extractions
// from one 32-bit word; no third-party dependency is warranted. The bit
// layout, the data-bit-rate table, and the modulation value→name table are
// taken from the Proxmark3 reference (doc/T5577_Guide.md + client
// cmdlft55xx.c GetModulationStr) and verified byte-for-byte against two
// real-world config words: 0x00148040 (EM4100 emulation → RF/64, Manchester,
// 2 blocks) and 0x00107060 (HID Prox → RF/50, FSK2a, 3 blocks) — not recalled.
//
// Layout (basic mode, bit 31 = MSB):
//
//	bits 31..28  Master Key (0x6 / 0x9 are the documented "extended mode" keys)
//	bits 27..21  reserved in basic mode (used in extended mode)
//	bits 20..18  Data Bit Rate (RF/8,16,32,40,50,64,100,128)
//	bit  17      reserved in basic mode
//	bits 16..12  Modulation
//	bits 11..10  PSK Clock Frequency (RF/2, RF/4, RF/8)
//	bit   9      Answer-On-Request (AOR)
//	bit   8      reserved in basic mode
//	bits  7.. 5  Max Block (number of data blocks)
//	bit   4      Password enabled (PWD)
//	bit   3      Sequence Terminator (ST)
//	bits  2.. 0  reserved / init-delay
//
// No confidently-wrong output: a modulation value outside the documented set
// is surfaced as a numeric code, not a guessed name; the decode assumes basic
// (non-extended) mode — the rarely-used extended mode reinterprets the
// reserved bits and is flagged but not decoded.
package t55xx

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// bitRates maps the 3-bit Data Bit Rate field to its RF/n divisor name.
var bitRates = []string{"RF/8", "RF/16", "RF/32", "RF/40", "RF/50", "RF/64", "RF/100", "RF/128"}

// pskClockFreqs maps the 2-bit PSK Clock Frequency field (meaningful only when
// the modulation is a PSK variant).
var pskClockFreqs = []string{"RF/2", "RF/4", "RF/8", "reserved"}

// modulations maps the 5-bit modulation field to its name
// (Proxmark3 cmdlft55xx.c GetModulationStr).
var modulations = map[int]string{
	0:    "Direct (ASK/NRZ)",
	1:    "PSK1",
	2:    "PSK2",
	3:    "PSK3",
	4:    "FSK1 (RF/8, RF/5)",
	5:    "FSK2 (RF/8, RF/10)",
	6:    "FSK1a (RF/5, RF/8)",
	7:    "FSK2a (RF/10, RF/8)",
	8:    "ASK / Manchester",
	16:   "Biphase",
	17:   "Reserved",
	0x18: "Biphase a (CDP)",
}

// Config is a decoded T5577 configuration register.
type Config struct {
	Raw                string   `json:"raw"`
	MasterKey          int      `json:"master_key"`
	DataBitRate        string   `json:"data_bit_rate"`
	DataBitRateRaw     int      `json:"data_bit_rate_raw"`
	Modulation         string   `json:"modulation"`
	ModulationRaw      int      `json:"modulation_raw"`
	PSKClockFreq       string   `json:"psk_clock_freq,omitempty"`
	AnswerOnRequest    bool     `json:"answer_on_request"`
	MaxBlock           int      `json:"max_block"`
	PasswordEnabled    bool     `json:"password_enabled"`
	SequenceTerminator bool     `json:"sequence_terminator"`
	Notes              []string `json:"notes,omitempty"`
}

// EncodeParams are the raw field values for building a T5577 basic-mode config
// word (the inverse of Decode's raw fields).
type EncodeParams struct {
	MasterKey          int  // 0-15 (bits 28-31)
	DataBitRateRaw     int  // 0-7  (bits 18-20) — RF/8..RF/128
	ModulationRaw      int  // 0-31 (bits 12-16)
	PSKClock           int  // 0-3  (bits 10-11) — only used for PSK modulations (1-3)
	AnswerOnRequest    bool // bit 9
	MaxBlock           int  // 0-7  (bits 5-7)
	PasswordEnabled    bool // bit 4
	SequenceTerminator bool // bit 3
}

// Encode builds a 32-bit T5577 basic-mode config word from the raw field values
// — the inverse of Decode. Decode(Encode(p)) reproduces p's fields. The PSK
// clock bits are only written for the PSK modulations (1-3), matching how Decode
// surfaces them. Out-of-range fields are rejected.
func Encode(p EncodeParams) (uint32, error) {
	for _, f := range []struct {
		name  string
		v, hi int
	}{
		{"master_key", p.MasterKey, 15},
		{"data_bit_rate_raw", p.DataBitRateRaw, 7},
		{"modulation_raw", p.ModulationRaw, 31},
		{"psk_clock", p.PSKClock, 3},
		{"max_block", p.MaxBlock, 7},
	} {
		if f.v < 0 || f.v > f.hi {
			return 0, fmt.Errorf("t55xx: %s %d out of range [0, %d]", f.name, f.v, f.hi)
		}
	}
	var b uint32
	b |= uint32(p.MasterKey&0x0F) << 28
	b |= uint32(p.DataBitRateRaw&0x07) << 18
	b |= uint32(p.ModulationRaw&0x1F) << 12
	if p.ModulationRaw >= 1 && p.ModulationRaw <= 3 {
		b |= uint32(p.PSKClock&0x03) << 10
	}
	if p.AnswerOnRequest {
		b |= 1 << 9
	}
	b |= uint32(p.MaxBlock&0x07) << 5
	if p.PasswordEnabled {
		b |= 1 << 4
	}
	if p.SequenceTerminator {
		b |= 1 << 3
	}
	return b, nil
}

// EncodeHex is Encode rendered as an 8-hex-digit upper-case config word.
func EncodeHex(p EncodeParams) (string, error) {
	b, err := Encode(p)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%08X", b), nil
}

// DecodeHex decodes a hex-encoded 32-bit config word (8 hex digits;
// ':' / '-' / '_' / whitespace and an optional 0x prefix tolerated).
func DecodeHex(s string) (*Config, error) {
	clean := strings.NewReplacer(":", "", "-", "", "_", "", " ", "", "\n", "", "\t", "").Replace(s)
	clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
	if clean == "" {
		return nil, fmt.Errorf("t55xx: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("t55xx: invalid hex: %w", err)
	}
	if len(b) != 4 {
		return nil, fmt.Errorf("t55xx: config word must be 4 bytes (8 hex digits), got %d bytes", len(b))
	}
	block0 := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return Decode(block0), nil
}

// Decode decodes a 32-bit T5577 configuration register (basic mode).
func Decode(block0 uint32) *Config {
	c := &Config{
		Raw:                fmt.Sprintf("%08X", block0),
		MasterKey:          int((block0 >> 28) & 0x0F),
		DataBitRateRaw:     int((block0 >> 18) & 0x07),
		ModulationRaw:      int((block0 >> 12) & 0x1F),
		AnswerOnRequest:    (block0>>9)&0x01 == 1,
		MaxBlock:           int((block0 >> 5) & 0x07),
		PasswordEnabled:    (block0>>4)&0x01 == 1,
		SequenceTerminator: (block0>>3)&0x01 == 1,
	}
	c.DataBitRate = bitRates[c.DataBitRateRaw]
	if name, ok := modulations[c.ModulationRaw]; ok {
		c.Modulation = name
	} else {
		c.Modulation = fmt.Sprintf("unmapped (code 0x%02X — see ATA5577 datasheet)", c.ModulationRaw)
	}
	// PSK clock frequency is only meaningful for the PSK modulations (1-3).
	if c.ModulationRaw >= 1 && c.ModulationRaw <= 3 {
		c.PSKClockFreq = pskClockFreqs[(block0>>10)&0x03]
	}
	if c.MasterKey == 0x6 || c.MasterKey == 0x9 {
		c.Notes = append(c.Notes,
			fmt.Sprintf("master-key nibble 0x%X selects extended mode; reserved bits are reinterpreted and are NOT decoded here (basic-mode decode shown)", c.MasterKey))
	}
	return c
}
