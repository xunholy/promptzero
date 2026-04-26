// SPDX-License-Identifier: AGPL-3.0-or-later
package crypto1

import (
	"context"
	"errors"
)

// AuthCapture represents one MIFARE Classic authentication exchange as
// captured by a passive sniffer or an attacker-controlled reader.
type AuthCapture struct {
	NT uint32 // Tag nonce (sent in plain)
	NR uint32 // Reader nonce (plain value — attacker knows it)
	AR uint32 // Encrypted reader auth response {aR}Ks sent on wire
}

// AuthEncrypt simulates the reader side of one MIFARE Classic
// authentication exchange and returns the encrypted (on-wire) values.
//
// Cipher sequence (Garcia et al. §3.3, reader perspective):
//
//  1. c.Init(key)                   — seed LFSR with the 48-bit sector key
//  2. c.CryptFeedback(uid ^ cap.NT) — advance LFSR through the nT phase
//  3. c.EncCrypt(cap.NR, 0)         — encrypt nR; plain nR feeds LFSR
//  4. ks2 = c.Crypt(0)              — aR-phase keystream
//
// Returned values:
//
//	nrEnc = {nR}Ks = cap.NR XOR ks1  (sent on wire)
//	arEnc = {aR}Ks = prng(cap.NT,64) XOR ks2  (sent on wire)
func AuthEncrypt(key uint64, uid uint32, cap AuthCapture) (nrEnc, arEnc uint32) {
	c := New()
	c.Init(key)
	c.CryptFeedback(uid ^ cap.NT)
	nrEnc = c.EncCrypt(cap.NR, 0)
	ks2 := c.Crypt(0)
	arEnc = Prng(cap.NT, 64) ^ ks2
	return nrEnc, arEnc
}

// Recover reconstructs the 48-bit MIFARE Classic sector key from two
// captured authentication exchanges (mfkey32v2 algorithm).
//
// Parameters:
//
//	uid           — card UID (4 bytes, big-endian)
//	nt0, nr0, ar0 — first-attempt:
//	                 nt0 = tag nonce (plain, received from tag)
//	                 nr0 = reader nonce (plain — the attacker chose it)
//	                 ar0 = {aR}Ks encrypted reader auth response on wire
//	nt1, nr1, ar1 — second-attempt (same card, same sector, different nonces)
//
// Returns the 48-bit key (low 48 bits of uint64) and an error if no
// candidate key matches both nonce-pairs.
//
// Algorithm: for each 48-bit candidate key K, simulate the auth exchange
// and compare the produced aR keystream against the constraint derived from
// the captured {aR} values.  Both captures must agree on the same K.
//
// From each capture: ks2 = {aR} XOR prng(nT, 64).
// The key K is correct when AuthEncrypt(K, uid, cap0) produces ks2_0
// AND AuthEncrypt(K, uid, cap1) produces ks2_1.
//
// Performance: this implementation is O(2^48) in the worst case for
// arbitrary 48-bit keys and may take hours.  For keys in a smaller
// search space (e.g. vendor-default keys or the low 24 bits unknown),
// supply keyHi via the keyspace argument (a range of hi-bit prefixes).
// If keyspace is nil, all 2^48 keys are searched — clearly document
// expected runtime in the caller.
//
// TODO(v0.6): implement the O(2^24) partial-state enumeration described
// in Garcia et al. ESORICS 2008 §4 ("filter-selectivity" technique).
// That approach enumerates 2^24 odd-bit candidates of the mid-auth LFSR
// state and uses the filter structure to derive remaining bits, reducing
// the search to a feasible runtime for arbitrary 48-bit keys.
func Recover(uid, nt0, nr0, ar0, nt1, nr1, ar1 uint32) (uint64, error) {
	return RecoverWithRange(context.Background(), uid, nt0, nr0, ar0, nt1, nr1, ar1, 0, 1<<32)
}

// RecoverWithRange is Recover with an explicit search range over the
// high 32 bits of the candidate key (bits 47..16).  loHi and hiHi are
// the inclusive-start and exclusive-end of the hi32 range.  The full
// 48-bit key is formed as (hi32 << 16) | lo16 for all lo16 in 0..65535.
//
// Use loHi=0, hiHi=1 to search only keys with bits 47..16 = 0
// (i.e. keys fitting in 16 bits), which completes in ~70 ms.
// Use loHi=0, hiHi=1<<32 to exhaustively search all 2^48 keys (hours).
//
// ctx is checked once per hi32 iteration; cancellation causes an early
// return of ctx.Err() so the caller's goroutine does not leak.
func RecoverWithRange(ctx context.Context, uid, nt0, nr0, ar0, nt1, nr1, ar1 uint32, loHi, hiHi uint64) (uint64, error) {
	// Derive the keystream used during the aR phase for each capture.
	// ks2 = {aR} XOR prng(nT, 64)  because the plain aR = prng(nT, 64).
	ks2_0 := ar0 ^ Prng(nt0, 64)
	ks2_1 := ar1 ^ Prng(nt1, 64)

	cap0 := AuthCapture{NT: nt0, NR: nr0}
	cap1 := AuthCapture{NT: nt1, NR: nr1}

	for hi32 := loHi; hi32 < hiHi; hi32++ {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		for lo16 := uint64(0); lo16 < (1 << 16); lo16++ {
			key := (hi32 << 16) | lo16

			// Simulate capture 0 and check keystream.
			c := New()
			c.Init(key)
			c.CryptFeedback(uid ^ cap0.NT)
			c.EncCrypt(cap0.NR, 0)
			ks2Got := c.Crypt(0)
			if ks2Got != ks2_0 {
				continue
			}

			// Capture 0 matched — verify capture 1.
			c.Init(key)
			c.CryptFeedback(uid ^ cap1.NT)
			c.EncCrypt(cap1.NR, 0)
			ks2Got1 := c.Crypt(0)
			if ks2Got1 == ks2_1 {
				return key, nil
			}
		}
	}

	return 0, errors.New("mfkey32: no matching key found in the specified key range")
}

// ksFromState returns the 32-bit keystream produced by clocking the
// Crypto1 LFSR 32 times (Crypt mode, no external feedback) from state.
// Operates on a copy; does not mutate the passed-in value.
func ksFromState(state uint64) uint32 {
	s := state & 0xFFFFFFFFFFFF
	var ks uint32
	for i := uint(0); i < 32; i++ {
		bit := filterOutput(s)
		fb := feedbackBit(s)
		s = (s >> 1) | (fb << 47)
		ks |= uint32(bit) << i
	}
	return ks
}

// rollback32 inverts 32 LFSR steps that were performed with the bits of
// inputWord (LSB-first, bit 0 = step 0) as the external feedback stream.
//
// The forward step for step i:
//
//	s_new = (s_old >> 1) | ((feedbackBit(s_old) XOR inputWord[i]) << 47)
//
// Inversion proceeds in REVERSE ORDER (step 31 undone first, then 30,
// ..., 0) so that each invertLFSRStep call correctly reverses its step.
func rollback32(state uint64, inputWord uint32) uint64 {
	s := state & 0xFFFFFFFFFFFF
	for i := 31; i >= 0; i-- {
		extBit := uint64((inputWord >> uint(i)) & 1)
		s = invertLFSRStep(s, extBit)
	}
	return s & 0xFFFFFFFFFFFF
}

// invertLFSRStep inverts a single LFSR right-shift step.
//
// Forward step: s_new = (s_old >> 1) | ((feedbackBit(s_old) XOR extBit) << 47)
//
// Inversion:
//
//	s_old = (s_new << 1) | lostBit
//
// where lostBit was at s_old[0] before the right-shift.  Solving:
//
//	s_new[47] = feedbackBit(s_old) XOR extBit
//	          = (lostBit XOR knownPart) XOR extBit
//	=> lostBit = s_new[47] XOR knownPart XOR extBit
//
// knownPart = XOR of the remaining LFSR taps (positions 5,9,10,...,43)
// evaluated at s_old; since s_old[p] = s_new[p-1] for p=1..47, these
// become s_new[4], s_new[8], ..., s_new[42].
func invertLFSRStep(sNew uint64, extBit uint64) uint64 {
	sNew &= 0xFFFFFFFFFFFF
	newHigh := sNew >> 47

	// s_old = (s_new << 1) | lostBit; evaluate known taps at s_old via s_new.
	// s_old[p] = s_new[p-1] for p = 1..47, so tap-p of s_old = bit (p-1) of s_new.
	knownPart := uint64(
		lfsr48bit(sNew, 4) ^ // tap 5:  s_old[5]  = s_new[4]
			lfsr48bit(sNew, 8) ^ // tap 9:  s_old[9]  = s_new[8]
			lfsr48bit(sNew, 9) ^ // tap 10: s_old[10] = s_new[9]
			lfsr48bit(sNew, 11) ^ // tap 12: s_old[12] = s_new[11]
			lfsr48bit(sNew, 13) ^ // tap 14: s_old[14] = s_new[13]
			lfsr48bit(sNew, 14) ^ // tap 15: s_old[15] = s_new[14]
			lfsr48bit(sNew, 16) ^ // tap 17: s_old[17] = s_new[16]
			lfsr48bit(sNew, 18) ^ // tap 19: s_old[19] = s_new[18]
			lfsr48bit(sNew, 23) ^ // tap 24: s_old[24] = s_new[23]
			lfsr48bit(sNew, 24) ^ // tap 25: s_old[25] = s_new[24]
			lfsr48bit(sNew, 26) ^ // tap 27: s_old[27] = s_new[26]
			lfsr48bit(sNew, 28) ^ // tap 29: s_old[29] = s_new[28]
			lfsr48bit(sNew, 34) ^ // tap 35: s_old[35] = s_new[34]
			lfsr48bit(sNew, 38) ^ // tap 39: s_old[39] = s_new[38]
			lfsr48bit(sNew, 40) ^ // tap 41: s_old[41] = s_new[40]
			lfsr48bit(sNew, 41) ^ // tap 42: s_old[42] = s_new[41]
			lfsr48bit(sNew, 42), // tap 43: s_old[43] = s_new[42]
	)

	lostBit := newHigh ^ knownPart ^ extBit
	sBase := (sNew << 1) & 0xFFFFFFFFFFFF
	return (sBase | lostBit) & 0xFFFFFFFFFFFF
}
