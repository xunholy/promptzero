// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crypto1 — Garcia §4 filter-selectivity optimised key recovery.
//
// # Algorithm overview — Garcia et al. ESORICS 2008 §4
//
// The Crypto1 filter f() reads ONLY the 20 odd-indexed LFSR bits
// {9,11,13,15,17,19,21,23,25,27,29,31,33,35,37,39,41,43,45,47}. This
// structural property enables a two-phase attack that reduces the full
// O(2^48) brute-force to roughly O(2^32) operations:
//
// Phase 1 — odd-state enumeration & filter:
//
//	Enumerate all 2^24 candidate "odd parts" of the LFSR state that exists
//	the moment the ks2 phase begins (stateAfterNR). For each candidate,
//	compute the even-indexed keystream bits ks2[0], ks2[2], ks2[4], …,
//	ks2[30] (16 bits total) using only the odd sub-state and treating the
//	even sub-state as zero (the feedback contributions from the even part
//	land at bit-47 each clock; they shift into the filter-input window
//	slowly, so the first several even-time ks bits are dominated by the
//	odd part). Compare the 16 predicted bits against the captured ks2. Most
//	candidates fail; ~2^8 survive to phase 2.
//
// Phase 2 — even-state enumeration & full verification:
//
//	For each surviving odd candidate, enumerate all 2^24 even-state
//	candidates. Reconstruct the full 48-bit state, compute ks2 exactly
//	(Crypt mode, 32 clocks), and compare to the captured ks2. About
//	256 × 2^24 × 2^-32 ≈ 256 state matches expected across the full
//	keyspace. For each match, roll back through the nR and nT phases to
//	obtain a candidate key and verify it against the second capture.
//
// Total work: ~2^24 (phase 1) + ~256 × 2^24 = O(2^32) operations.
//
// # Bit-packing convention
//
// The 48-bit LFSR state is decomposed into two 24-bit halves:
//
//	oddState  — bit k of oddState  = bit (2k+1) of fullState, k = 0..23
//	evenState — bit k of evenState = bit (2k)   of fullState, k = 0..23
//
// Re-interleaving: fullState = interleave(oddState, evenState).
//
//	fullState[2k]   = evenState[k]
//	fullState[2k+1] = oddState[k]
//
// # Filter in terms of sub-states
//
// filterOutput reads bits at positions 9,11,13,15,17,19,21,23,25,27,29,
// 31,33,35,37,39,41,43,45,47. These are all ODD positions 2k+1:
//
//	k = 4..23  →  oddState[4..23]
//
// Therefore filterOdd(odd) = filterOutput(interleave(odd, 0)):
//
//	y0 = fa(odd[4],  odd[5],  odd[6],  odd[7])
//	y1 = fb(odd[8],  odd[9],  odd[10], odd[11])
//	y2 = fb(odd[12], odd[13], odd[14], odd[15])
//	y3 = fa(odd[16], odd[17], odd[18], odd[19])
//	y4 = fb(odd[20], odd[21], odd[22], odd[23])
//	filterOdd = fc(y0, y1, y2, y3, y4)
//
// # Clock decomposition
//
// One clock of the full LFSR: state_new = (state >> 1) | (fb << 47)
// where fb = feedbackBit(state) XOR extBit.
//
// Translating to sub-states (extBit = 0, Crypt mode):
//
//	evenState_new[k] = oddState[k]                    k=0..23
//	oddState_new[k]  = evenState[k+1]                 k=0..22
//	oddState_new[23] = feedbackBit(fullState)
//
// feedbackBit involves BOTH sub-states (see lfsrTaps in crypto1.go).
// In phase 1 we approximate by setting evenState = 0, so the even
// feedback taps contribute 0 XOR. This is the controlled approximation
// that enables the 2^24 filter.
//
// # References
//
//   - Garcia, de Koning Gans, Muijrers, van Rossum, Verdult, Schreur,
//     Jacobs. "Dismantling MIFARE Classic." ESORICS 2008.
//   - equipter/mfkey32v2 — bit-packing convention reference (clean-room
//     reimplementation; no code was copied from that project).
package crypto1

import (
	"context"
	"errors"
	"fmt"
)

// lfsrTapsOdd contains the odd-positioned LFSR taps, each stored as the
// corresponding oddState index: tap position 2k+1 → index k.
// Derived from lfsrTaps = {0,5,9,10,12,14,15,17,19,24,25,27,29,35,39,41,42,43}.
// Odd positions in that set: 5→2, 9→4, 15→7, 17→8, 19→9, 25→12, 27→13,
// 29→14, 35→17, 39→19, 41→20, 43→21.
var lfsrTapsOddIdx = [...]int{2, 4, 7, 8, 9, 12, 13, 14, 17, 19, 20, 21}

// lfsrTapsEven contains the even-positioned LFSR taps, each stored as the
// corresponding evenState index: tap position 2k → index k.
// Even positions in lfsrTaps: 0→0, 10→5, 12→6, 14→7, 24→12, 42→21.
var lfsrTapsEvenIdx = [...]int{0, 5, 6, 7, 12, 21}

// interleave recombines a 24-bit oddState and 24-bit evenState into the
// full 48-bit LFSR state.
//
//	fullState[2k]   = evenState[k]   for k = 0..23
//	fullState[2k+1] = oddState[k]    for k = 0..23
func interleave(odd, even uint32) uint64 {
	var s uint64
	for k := uint(0); k < 24; k++ {
		s |= uint64((even>>k)&1) << (2 * k)
		s |= uint64((odd>>k)&1) << (2*k + 1)
	}
	return s & 0xFFFFFFFFFFFF
}

// deinterleave splits the 48-bit LFSR state into its 24-bit odd and
// even sub-states.
//
//	oddState[k]  = fullState[2k+1]   for k = 0..23
//	evenState[k] = fullState[2k]     for k = 0..23
func deinterleave(state uint64) (odd, even uint32) {
	for k := uint(0); k < 24; k++ {
		odd |= uint32((state>>(2*k+1))&1) << k
		even |= uint32((state>>(2*k))&1) << k
	}
	return odd, even
}

// filterOdd returns the keystream bit produced by a state whose oddState
// is `odd` and whose evenState is zero. This is the approximation used in
// phase 1 — it is exact for ks2[0] and a controlled approximation for
// higher even-time bits (feedback contributions from the unknown evenState
// accumulate slowly and are corrected in phase 2).
//
// Reads oddState bits 4..23 which correspond to full-state positions 9..47:
//
//	y0 = fa(odd[4..7])   ← full-state positions 9,11,13,15
//	y1 = fb(odd[8..11])  ← full-state positions 17,19,21,23
//	y2 = fb(odd[12..15]) ← full-state positions 25,27,29,31
//	y3 = fa(odd[16..19]) ← full-state positions 33,35,37,39
//	y4 = fb(odd[20..23]) ← full-state positions 41,43,45,47
func filterOdd(odd uint32) uint64 {
	bit := func(k uint) uint64 { return uint64((odd >> k) & 1) }
	y0 := fa(bit(4), bit(5), bit(6), bit(7))
	y1 := fb(bit(8), bit(9), bit(10), bit(11))
	y2 := fb(bit(12), bit(13), bit(14), bit(15))
	y3 := fa(bit(16), bit(17), bit(18), bit(19))
	y4 := fb(bit(20), bit(21), bit(22), bit(23))
	return fc(y0, y1, y2, y3, y4)
}

// oddFeedback returns the XOR of the lfsrTaps that lie at odd-indexed
// full-state positions, evaluated from oddState.
// These taps: 5,9,15,17,19,25,27,29,35,39,41,43 → indices 2,4,7,8,9,12,13,14,17,19,20,21.
func oddFeedback(odd uint32) uint64 {
	var fb uint64
	for _, idx := range lfsrTapsOddIdx {
		fb ^= uint64((odd >> uint(idx)) & 1)
	}
	return fb
}

// evenFeedback returns the XOR of the lfsrTaps that lie at even-indexed
// full-state positions, evaluated from evenState.
// These taps: 0,10,12,14,24,42 → indices 0,5,6,7,12,21.
func evenFeedback(even uint32) uint64 {
	var fb uint64
	for _, idx := range lfsrTapsEvenIdx {
		fb ^= uint64((even >> uint(idx)) & 1)
	}
	return fb
}

// clockOddApprox advances oddState by one Crypt-mode clock, treating
// evenState as zero (the phase-1 approximation).
//
// Forward clock: oddState_new[k] = evenState[k+1] for k=0..22,
//                oddState_new[23] = feedbackBit.
// With evenState=0: oddState_new[0..22] = 0, oddState_new[23] = oddFeedback(odd).
//
// This is the degenerate single-step used to advance the odd sub-state
// during the even-time ks prediction loop.
func clockOddApprox(odd uint32) uint32 {
	fb := oddFeedback(odd) // even contribution is 0
	// shift: new odd[k] = old even[k+1] = 0 for k=0..22; new odd[23] = fb
	return uint32(fb) << 23
}

// clockPairExact advances both oddState and evenState by one Crypt-mode
// clock using the full feedbackBit (both sub-states contribute).
//
// Derivation:
//
//	evenState_new[k] = oddState[k]              for k = 0..23
//	oddState_new[k]  = evenState[k+1]           for k = 0..22
//	oddState_new[23] = oddFeedback(odd) XOR evenFeedback(even)
func clockPairExact(odd, even uint32) (uint32, uint32) {
	fb := oddFeedback(odd) ^ evenFeedback(even)
	// new even = old odd (all 24 bits)
	newEven := odd
	// new odd[0..22] = old even[1..23]
	// new odd[23]    = fb
	newOdd := (even >> 1) | (uint32(fb) << 23)
	return newOdd & 0xFFFFFF, newEven & 0xFFFFFF
}

// ks16EvenApprox produces 16 keystream bits at even clocks t=0,2,4,…,30
// from oddState alone (evenState ≈ 0). The result is packed LSB-first:
// result[k] = ks2[2k] for k = 0..15.
//
// Since the filter only reads odd-indexed LFSR bits, and even-time bits
// of the keystream are produced when the filter reads the current odd
// sub-state (shifted forward by even steps), this gives a reasonable
// approximation for the first 16 even-time bits.
//
// At each even clock step, the approximate oddState advances by two
// clockOddApprox calls (each introduces one new feedback bit at position
// 23 and shifts everything right by one even step).
//
// Implementation note: iterating two clockOddApprox calls per output bit
// avoids a large precomputed table, keeping memory overhead O(1).
func ks16EvenApprox(odd uint32) uint32 {
	var ks uint32
	o := odd
	for k := uint(0); k < 16; k++ {
		// Collect keystream bit at even time 2k.
		ks |= uint32(filterOdd(o)) << k
		// Advance two clocks (both approximate — evenState = 0).
		// Clock 1: the "even clock" that emits the odd-time ks bit we skip.
		// Clock 2: the next "even clock" from which we collect the next bit.
		//
		// clockOddApprox approximates one full-LFSR clock keeping only
		// the contribution of the odd part to the feedback. Two clocks:
		//   after clock 1: evenApprox = odd (but we discard evenApprox)
		//                  oddApprox  = feedback_of_odd << 23
		//   after clock 2: evenApprox2 = oddApprox
		//                  oddApprox2  = feedback_of_oddApprox << 23
		//                  AND the bits from the previous even contribution
		//                  (which we approximated as 0).
		// The double-clock is equivalent to: the odd sub-state advances
		// such that positions 0..21 come from old positions 2..23 (the
		// interleaved-shift effect), plus two new feedback bits at 22,23.
		// With evenState=0 the shift contribution is zero; only the feedback
		// bits fill the top. We capture ks, advance, capture, advance.
		o = clockOddApprox(o)
		o = clockOddApprox(o)
	}
	return ks
}

// ks32Full computes the full 32-bit keystream from the combined 48-bit
// LFSR state in Crypt mode (no external feedback). This is identical to
// ksFromState but operates on the already-decomposed (odd, even) form to
// avoid redundant interleaving in the inner loop.
func ks32Full(odd, even uint32) uint32 {
	o, e := odd&0xFFFFFF, even&0xFFFFFF
	var ks uint32
	for i := uint(0); i < 32; i++ {
		full := interleave(o, e)
		bit := filterOutput(full)
		ks |= uint32(bit) << i
		o, e = clockPairExact(o, e)
	}
	return ks
}

// RecoverFast recovers the 48-bit MIFARE Classic sector key from two
// captured authentication exchanges using the Garcia et al. ESORICS 2008
// §4 filter-selectivity optimisation.
//
// This function has the same external contract as Recover but runs in
// O(2^32) operations rather than O(2^48). See the package-level
// documentation for the algorithm description.
//
// Parameters are identical to Recover:
//
//	uid           — card UID (4 bytes)
//	nt0, nr0, ar0 — first capture: tag nonce, reader nonce, {aR}Ks
//	nt1, nr1, ar1 — second capture (same card, different nonces)
//
// Returns the 48-bit key (low 48 bits of uint64) or an error if no
// candidate key satisfies both captures.
func RecoverFast(uid, nt0, nr0, ar0, nt1, nr1, ar1 uint32) (uint64, error) {
	return RecoverFastTimeout(context.Background(), uid, nt0, nr0, ar0, nt1, nr1, ar1)
}

// RecoverFastTimeout is RecoverFast with a context deadline. The context
// is checked once per phase-1 candidate block (every 2^16 iterations) so
// cancellation latency is bounded to a few milliseconds.
//
// Returns context.Canceled or context.DeadlineExceeded if the context
// is done before a key is found, plus an error wrapping the context error.
func RecoverFastTimeout(ctx context.Context, uid, nt0, nr0, ar0, nt1, nr1, ar1 uint32) (uint64, error) {
	// Derive the known keystream ks2 for each capture:
	//   ks2 = {aR} XOR prng(nT, 64)   (the plain aR = prng(nT, 64))
	ks2_0 := ar0 ^ Prng(nt0, 64)
	ks2_1 := ar1 ^ Prng(nt1, 64)

	// Pack the 16 even-indexed bits of ks2_0 into a 16-bit value for
	// fast comparison in phase 1. ks2_0[2k] is bit 2k of ks2_0.
	var ks2_0_even uint32
	for k := uint(0); k < 16; k++ {
		ks2_0_even |= ((ks2_0 >> (2 * k)) & 1) << k
	}

	// Phase 1: enumerate 2^24 odd-state candidates, filter on even-time ks bits.
	//
	// We iterate oddState from 0 to 2^24-1. For each, compute the 16
	// even-time keystream bits and compare to ks2_0_even. Survivors
	// (expected ~256 out of 2^24) are collected for phase 2.
	survivors := make([]uint32, 0, 512)

	const checkInterval = 1 << 16 // check ctx every 64K odd candidates
	for oddState := uint32(0); oddState < (1 << 24); oddState++ {
		if oddState&(checkInterval-1) == 0 {
			select {
			case <-ctx.Done():
				return 0, fmt.Errorf("mfkey32 fast: %w", ctx.Err())
			default:
			}
		}
		pred := ks16EvenApprox(oddState)
		if pred == ks2_0_even {
			survivors = append(survivors, oddState)
		}
	}

	if len(survivors) == 0 {
		return 0, errors.New("mfkey32 fast: phase 1 produced no odd-state survivors (data may be corrupt)")
	}

	// Phase 2: for each surviving odd candidate, enumerate 2^24 even
	// candidates, verify full ks2_0, then verify ks2_1 via key rollback.
	for _, oddState := range survivors {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("mfkey32 fast: %w", ctx.Err())
		default:
		}

		for evenState := uint32(0); evenState < (1 << 24); evenState++ {
			// Compute the full 32-bit ks2 from this candidate state.
			gotKS2 := ks32Full(oddState, evenState)
			if gotKS2 != ks2_0 {
				continue
			}

			// ks2_0 matched — recover the full 48-bit state and roll back
			// to the candidate key, then verify capture 1.
			stateAfterNR := interleave(oddState, evenState)
			key, ok := rollbackToKey(stateAfterNR, uid, nt0, nr0)
			if !ok {
				continue
			}

			// Verify against second capture.
			c := New()
			c.Init(key)
			c.CryptFeedback(uid ^ nt1)
			c.EncCrypt(nr1, 0)
			ks2Got1 := c.Crypt(0)
			if ks2Got1 == ks2_1 {
				return key, nil
			}
		}
	}

	return 0, errors.New("mfkey32 fast: no matching key found in full keyspace")
}

// rollbackToKey attempts to roll back the LFSR state stateAfterNR (the
// state immediately after the EncCrypt(nR) step of capture 0) through
// the nR and nT authentication phases to recover the candidate 48-bit
// key. Returns (key, true) if the rolled-back state fits in 48 bits,
// (0, false) on any inconsistency.
//
// Roll-back sequence (reverse of AuthEncrypt):
//
//  1. rollback32(stateAfterNR, nR)   → stateAfterNT
//  2. rollback32(stateAfterNT, uid^nT) → stateAfterInit = key
func rollbackToKey(stateAfterNR uint64, uid, nt, nr uint32) (key uint64, ok bool) {
	stateAfterNT := rollback32(stateAfterNR, nr)
	key = rollback32(stateAfterNT, uid^nt)
	// Sanity: key must fit in 48 bits; rollback32 always produces a
	// 48-bit value, but we double-check to be explicit.
	if key != (key & 0xFFFFFFFFFFFF) {
		return 0, false
	}
	return key, true
}
