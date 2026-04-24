// SPDX-License-Identifier: AGPL-3.0-or-later

// Package keeloq implements the KeeLoq block cipher and supporting
// primitives for sub-GHz rolling-code analysis.
//
// KeeLoq is a 32-bit block cipher with a 64-bit key and 528 rounds,
// designed by Willem Smit and later acquired by Microchip Technology.
// It is used in automotive and garage-door remote keyless-entry systems
// (Microchip HCS200, HCS300, HCS360, HCS410, etc.). The algorithm is
// based on a nonlinear feedback shift register (NLFSR).
//
// # Algorithm summary
//
// Encryption operates on a 32-bit state y and a 64-bit key k:
//
//	for i in 0..527:
//	    bit = NLF(y[31], y[26], y[20], y[9], y[1]) XOR y[16] XOR y[0] XOR k[i mod 64]
//	    y   = (y >> 1) | (bit << 31)
//
// Decryption inverts each round. Given the post-round state y_new, the
// pre-round state y_old is recovered as follows. Because y_new = (y_old >> 1)
// | (bit << 31), we have y_old[i+1] = y_new[i] for i in 0..30, so
// y_old = (y_new << 1) | bit_0, where bit_0 is the recovered low bit:
//
//	bit_0 = y_new[31] XOR NLF(y_new[30], y_new[25], y_new[19], y_new[8], y_new[0])
//	                   XOR y_new[15] XOR k[i mod 64]
//
// # Security posture
//
// KeeLoq was publicly broken by Bogdanov (2007) and Courtois et al. (2008).
// Several manufacturer master keys are published in the academic literature
// (see manufacturer.go). This package is intended for authorised security
// testing and educational use only. PromptZero is licensed AGPL-3.0-or-later.
//
// # References
//
//   - Microchip Technology AN66115 "Code Hopping Encoder Using the HCS301"
//   - A. Bogdanov, "Cryptanalysis of the KeeLoq block cipher," IACR ePrint
//     2007/055, 2007.
//   - N. T. Courtois, G. Bard, D. Wagner, "Algebraic and Slide Attacks on
//     KeeLoq," FSE 2008, LNCS 5086.
//   - T. Eisenbarth, T. Kasper, A. Moradi, C. Paar, M. Salmasizadeh,
//     M. T. M. Shalmani, "On the Power of Power Analysis in the Real World:
//     A Complete Break of the KeeLoq Code Hopping Scheme," CRYPTO 2008.
package keeloq

// nlf is the precomputed 32-entry lookup for the nonlinear filter function.
// The 5-input Boolean function is derived from the S-box constant 0x3A5C742E.
// Entry index encodes (a<<4 | b<<3 | c<<2 | d<<1 | e) for inputs a..e,
// each a single bit. The function value is bit (index) of 0x3A5C742E.
var nlf [32]uint32

func init() {
	const sbox uint64 = 0x3A5C742E
	for i := uint32(0); i < 32; i++ {
		nlf[i] = uint32((sbox >> i) & 1)
	}
}

// NLF is the nonlinear filter function used in each KeeLoq round.
// Each argument must be a single bit (0 or 1); the 5-bit index
// selects from the precomputed lookup derived from S-box 0x3A5C742E.
// NLF is exported for testing and for external callers that wish to
// verify the lookup table independently.
func NLF(a, b, c, d, e uint32) uint32 {
	return nlf[(a<<4)|(b<<3)|(c<<2)|(d<<1)|e]
}

// Encrypt encrypts a 32-bit plaintext under a 64-bit key using 528 rounds
// of the KeeLoq NLFSR. The result is a 32-bit ciphertext.
func Encrypt(plaintext uint32, key uint64) uint32 {
	y := plaintext
	for i := uint32(0); i < 528; i++ {
		keyBit := uint32((key >> (i % 64)) & 1)
		bit := NLF(y>>31&1, y>>26&1, y>>20&1, y>>9&1, y>>1&1) ^
			(y >> 16 & 1) ^
			(y & 1) ^
			keyBit
		y = (y >> 1) | (bit << 31)
	}
	return y
}

// Decrypt is the inverse of Encrypt. It recovers the 32-bit plaintext from
// a 32-bit ciphertext and the same 64-bit key used during encryption.
// The 528 rounds are traversed in reverse order; see the package doc for
// the derivation of the inverse tap positions.
func Decrypt(ciphertext uint32, key uint64) uint32 {
	y := ciphertext
	for i := uint32(527); ; i-- {
		keyBit := uint32((key >> (i % 64)) & 1)
		// Recover the bit that was shifted into the low position during
		// the forward round. The tap positions in y (which equals y_new)
		// are derived from the forward taps by subtracting 1 from each
		// position (since y_old[j+1] = y_new[j]).
		bit := (y >> 31 & 1) ^
			NLF(y>>30&1, y>>25&1, y>>19&1, y>>8&1, y&1) ^
			(y >> 15 & 1) ^
			keyBit
		y = (y << 1) | bit
		if i == 0 {
			break
		}
	}
	return y
}

// IsValidHCS performs a lightweight plausibility check on a decrypted
// KeeLoq block as produced by Microchip HCS-series encoders. It is used
// by brute-force routines to score candidate keys with reduced false
// positives, without requiring a full replay of the rolling counter.
//
// HCS block layout (32 bits, MSB first):
//
//	bits 31..28  — button code  (4 bits; valid values 1-15, 0 is unused)
//	bits 27..16  — overflow / status (12 bits, all zero in normal operation)
//	bits 15..0   — 16-bit rolling counter (lower 16 bits of a 16-bit counter)
//
// IsValidHCS returns true when the button nibble is non-zero and the
// 12-bit status field is zero. It does NOT validate the counter because
// a single intercepted transmission gives no monotonic reference.
func IsValidHCS(decrypted uint32) bool {
	button := (decrypted >> 28) & 0xF
	status := (decrypted >> 16) & 0xFFF
	return button != 0 && status == 0
}
