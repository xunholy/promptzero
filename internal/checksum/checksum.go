// SPDX-License-Identifier: AGPL-3.0-or-later

// Package checksum computes and identifies the common NON-CRC frame checksums
// — plain modular sums, XOR/LRC, the Modbus two's-complement LRC, and the
// Fletcher checksums. It is the companion to the CRC catalogue (internal/crc)
// in the protocol reverse-engineering toolkit: when a captured frame ends in a
// trailer that is not a CRC — the common case for cheap RF remotes, sensors,
// and simple serial devices, which favour a one-line sum or XOR — this finds
// which simple checksum reproduces it.
//
// # Wrap-vs-native judgement
//
// Native. These are one-liners (a running sum or XOR, the Fletcher double
// accumulator). There is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The sum / XOR / LRC algorithms are definitional and hand-computable; the
// Fletcher checksums carry the published reference vectors used as the unit
// tests' oracle (Fletcher-16 of "abcdefgh" = 0x0627, Fletcher-32 of "abcde" =
// 0xF04FC729). The identify mode makes no guesses: it reports the algorithms
// whose output equals the supplied checksum, and an empty result is an honest
// "no simple checksum matches" (try internal/crc for the CRC families).
//
// # Covered / deferred
//
// Covered: SUM-8, SUM-16, XOR-8 (LRC), Modbus LRC, Fletcher-16, Fletcher-32.
// Adler-32 (Go stdlib hash/adler32) and CRCs (internal/crc) are out of scope.
package checksum

import "fmt"

// Algo is one named simple-checksum algorithm.
type Algo struct {
	Name  string `json:"name"`
	Width int    `json:"width"` // bits, for formatting
	fn    func([]byte) uint32
}

// Compute applies the algorithm to data.
func (a Algo) Compute(data []byte) uint32 { return a.fn(data) }

// Format renders a value as width-appropriate hex.
func (a Algo) Format(v uint32) string { return fmt.Sprintf("0x%0*X", a.Width/4, v) }

// Algos is the supported set.
var Algos = []Algo{
	{"SUM-8", 8, sum8},
	{"SUM-16", 16, sum16},
	{"XOR-8 (LRC)", 8, xor8},
	{"LRC-MODBUS", 8, modbusLRC},
	{"FLETCHER-16", 16, fletcher16},
	{"FLETCHER-32", 32, fletcher32},
}

// Match is one identify result.
type Match struct {
	Algo  string `json:"algo"`
	Width int    `json:"width"`
}

// Identify returns the algorithms whose checksum of data equals want.
func Identify(data []byte, want uint32) []Match {
	var out []Match
	for _, a := range Algos {
		mask := uint32((uint64(1) << uint(a.Width)) - 1)
		if a.Width >= 32 {
			mask = 0xFFFFFFFF
		}
		if a.Compute(data) == want&mask {
			out = append(out, Match{Algo: a.Name, Width: a.Width})
		}
	}
	return out
}

// Lookup returns the named algorithm.
func Lookup(name string) (Algo, bool) {
	for _, a := range Algos {
		if a.Name == name {
			return a, true
		}
	}
	return Algo{}, false
}

func sum8(data []byte) uint32 {
	var s uint32
	for _, b := range data {
		s += uint32(b)
	}
	return s & 0xFF
}

func sum16(data []byte) uint32 {
	var s uint32
	for _, b := range data {
		s += uint32(b)
	}
	return s & 0xFFFF
}

func xor8(data []byte) uint32 {
	var x byte
	for _, b := range data {
		x ^= b
	}
	return uint32(x)
}

// modbusLRC is the Modbus-ASCII LRC: the two's complement of the 8-bit sum.
func modbusLRC(data []byte) uint32 {
	return (-sum8(data)) & 0xFF
}

// fletcher16 — two mod-255 accumulators over the bytes.
func fletcher16(data []byte) uint32 {
	var s1, s2 uint32
	for _, b := range data {
		s1 = (s1 + uint32(b)) % 255
		s2 = (s2 + s1) % 255
	}
	return s2<<8 | s1
}

// fletcher32 — two mod-65535 accumulators over little-endian 16-bit words (a
// trailing odd byte is taken as the low byte of the final word).
func fletcher32(data []byte) uint32 {
	var s1, s2 uint32
	for i := 0; i < len(data); i += 2 {
		w := uint32(data[i])
		if i+1 < len(data) {
			w |= uint32(data[i+1]) << 8
		}
		s1 = (s1 + w) % 65535
		s2 = (s2 + s1) % 65535
	}
	return s2<<16 | s1
}
