// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crc computes and identifies cyclic redundancy checks against the
// standard CRC catalogue (the parameters Greg Cook's reveng catalogue
// publishes). It is a protocol reverse-engineering aid: when a captured RF or
// wired frame ends in a checksum of an unknown algorithm — the constant case
// when bringing up a new decoder — this computes the CRC under each catalogue
// model, and the identify mode reports which model(s) reproduce an observed
// CRC over the data.
//
// # Wrap-vs-native judgement
//
// Native. A CRC is a parameterised bit-walk — (width, polynomial, init,
// reflect-in, reflect-out, xor-out) — about thirty lines of shift/xor. There
// is nothing to wrap, and the project already computes specific CRCs inline
// across its decoders (canfd, adsb, pocsag); this generalises that into a
// reusable catalogue.
//
// # Verifiable / no confidently-wrong output
//
// Every model in the catalogue carries its published "check" value — the CRC
// of the ASCII string "123456789", the universal CRC self-test vector. The
// unit tests assert that this package computes exactly that check value for
// every model, so a model only ships if its parameters reproduce the
// authoritative reference. The identify mode makes no guesses: it reports the
// models whose output equals the supplied CRC, and an empty result is an
// honest "no catalogue model matches".
//
// # Covered / deferred
//
// Covered: the common CRC-8 / CRC-16 / CRC-32 models seen in embedded, RF, and
// fieldbus protocols (each with a published check value). Wider/rarer widths
// (CRC-5/USB, CRC-24, CRC-64) and the full reveng search (brute-forcing
// unknown polynomials) are deliberately out of scope here.
package crc

import "fmt"

// Model is one parameterised CRC algorithm.
type Model struct {
	Name   string `json:"name"`
	Width  int    `json:"width"`
	Poly   uint32 `json:"poly"`
	Init   uint32 `json:"init"`
	RefIn  bool   `json:"ref_in"`
	RefOut bool   `json:"ref_out"`
	XorOut uint32 `json:"xor_out"`
	Check  uint32 `json:"check"` // CRC of "123456789"
}

// Catalogue is the set of supported CRC models. Each Check value is from the
// reveng catalogue and is asserted by the unit tests.
var Catalogue = []Model{
	{"CRC-8/SMBUS", 8, 0x07, 0x00, false, false, 0x00, 0xF4},
	{"CRC-8/MAXIM-DOW", 8, 0x31, 0x00, true, true, 0x00, 0xA1}, // Dallas/Maxim 1-Wire
	{"CRC-16/ARC", 16, 0x8005, 0x0000, true, true, 0x0000, 0xBB3D},
	{"CRC-16/CCITT-FALSE", 16, 0x1021, 0xFFFF, false, false, 0x0000, 0x29B1},
	{"CRC-16/XMODEM", 16, 0x1021, 0x0000, false, false, 0x0000, 0x31C3},
	{"CRC-16/MODBUS", 16, 0x8005, 0xFFFF, true, true, 0x0000, 0x4B37},
	{"CRC-16/KERMIT", 16, 0x1021, 0x0000, true, true, 0x0000, 0x2189},
	{"CRC-32/ISO-HDLC", 32, 0x04C11DB7, 0xFFFFFFFF, true, true, 0xFFFFFFFF, 0xCBF43926}, // zip, Ethernet, PNG
	{"CRC-32/BZIP2", 32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF, 0xFC891918},
	{"CRC-32/MPEG-2", 32, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000, 0x0376E6E7},
}

// Compute returns the CRC of data under model m.
func (m Model) Compute(data []byte) uint32 {
	mask := widthMask(m.Width)
	topBit := uint32(1) << uint(m.Width-1)
	crc := m.Init & mask
	for _, b := range data {
		if m.RefIn {
			b = reflect8(b)
		}
		crc ^= uint32(b) << uint(m.Width-8)
		for i := 0; i < 8; i++ {
			if crc&topBit != 0 {
				crc = (crc << 1) ^ m.Poly
			} else {
				crc <<= 1
			}
			crc &= mask
		}
	}
	if m.RefOut {
		crc = reflectN(crc, m.Width)
	}
	return (crc ^ m.XorOut) & mask
}

// Match is one identify result.
type Match struct {
	Model string `json:"model"`
	Width int    `json:"width"`
}

// Identify returns the catalogue models whose CRC of data equals want.
func Identify(data []byte, want uint32) []Match {
	var out []Match
	for _, m := range Catalogue {
		if m.Compute(data) == want&widthMask(m.Width) {
			out = append(out, Match{Model: m.Name, Width: m.Width})
		}
	}
	return out
}

// Lookup returns the named model.
func Lookup(name string) (Model, bool) {
	for _, m := range Catalogue {
		if m.Name == name {
			return m, true
		}
	}
	return Model{}, false
}

// Format renders a CRC value as width-appropriate hex.
func (m Model) Format(v uint32) string {
	return fmt.Sprintf("0x%0*X", m.Width/4, v)
}

func widthMask(width int) uint32 {
	if width >= 32 {
		return 0xFFFFFFFF
	}
	return (uint32(1) << uint(width)) - 1
}

func reflect8(b byte) byte {
	var r byte
	for i := 0; i < 8; i++ {
		if b&(1<<uint(i)) != 0 {
			r |= 1 << uint(7-i)
		}
	}
	return r
}

func reflectN(v uint32, width int) uint32 {
	var r uint32
	for i := 0; i < width; i++ {
		if v&(1<<uint(i)) != 0 {
			r |= 1 << uint(width-1-i)
		}
	}
	return r
}
