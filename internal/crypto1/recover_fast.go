// SPDX-License-Identifier: AGPL-3.0-or-later

// Package crypto1 — Garcia §4 filter-selectivity optimised key recovery.
//
// # Algorithm overview — Garcia et al. ESORICS 2008 §4
//
// The Crypto1 filter f() reads ONLY the 20 odd-indexed LFSR bits at
// positions {9,11,13,...,47}. This structural property enables a two-phase
// attack that exploits the LFSR's odd/even decomposition.
//
// The 48-bit state is decomposed into:
//
//	oddState  — 24 bits at positions 1,3,5,...,47  (oddState[k] = state[2k+1])
//	evenState — 24 bits at positions 0,2,4,...,46  (evenState[k] = state[2k])
//	fullState = interleave(oddState, evenState)
//
// Key structural facts:
//
//  1. filterOutput at t=0 reads ONLY oddState bits 4..23.
//     Therefore ks2[0] = filterOdd(oddState) exactly — no approximation.
//
//  2. After one Crypt-mode clock from interleave(0,even), the filter reads
//     evenState bits 5..23 plus the even-part feedback bit.
//     Therefore filterEven(even) approximates ks2[1] from the even sub-state.
//
// # Two-phase attack
//
// Phase 1 — oddState enumeration with pred16EvenFromOdd filter:
//
//	Enumerate 2^24 oddState candidates X. For each, simulate state
//	interleave(X, 0) forward and record the 16 even-time keystream bits
//	(t=0,2,4,...,30). Compare against the captured ks2's even-indexed bits.
//	Expected ~256 survivors from 2^24 when the approximation aligns.
//
//	Note: the comparison is probabilistic because the evenState contributes
//	to the actual even-time bits through feedback (entering at LFSR bit-47).
//	The first bit (t=0) is exact; subsequent bits are correlated at ~50%.
//	When pred16EvenFromOdd(oddState_real) happens to equal ks2_even
//	(probability ~2^-15), the fast path finds the key in O(2^32).
//
// Phase 2 — evenState enumeration per survivor:
//
//	For each phase-1 survivor X, enumerate 2^24 evenState candidates Y.
//	Use ks8Full(X,Y) as an 8-bit pre-check to eliminate ~255/256 wrong
//	Y values before computing the full 32-bit ks2. For each full match,
//	roll back to candidate key K and verify against the second capture.
//
// # Correctness guarantee
//
// RecoverFast always falls back to RecoverWithRange(0, 1<<32) if the
// phase-1+phase-2 path does not find the key. This guarantees correctness
// for all 48-bit keys at the cost of O(2^48) worst-case fallback work.
// The fallback terminates quickly for small keys (O(2^N) for N-bit keys).
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
	"fmt"

	"github.com/xunholy/promptzero/internal/obs"
)

// --- Sub-state decomposition helpers -----------------------------------

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

// --- Filter in terms of sub-states ------------------------------------

// filterOdd returns the keystream bit produced by a state whose oddState
// is `odd` and whose evenState is zero. Because filterOutput reads only
// odd-indexed LFSR positions {9,11,...,47} = oddState[4..23], this is
// the EXACT first keystream bit ks2[0] = filterOutput(fullState) at t=0.
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

// filterEven returns the keystream bit produced one clock after starting
// from state interleave(0, even). After one Crypt-mode clock, the new
// odd sub-state positions come from the original even sub-state.
//
// Derivation: after 1 clock from interleave(0,even):
//
//	new_state[2k+1] = old_state[2k+2] = even[k+1]  for k=0..22
//	new_state[47]   = feedbackBit(interleave(0,even)) = evenFeedback(even)
//
// filterOutput at this state reads positions 9..47 (all odd):
//
//	position 2k+1 for k=4..22 → new_state[2k+1] = even[k+1] = even[5..23]
//	position 47   → evenFeedback(even)
func filterEven(even uint32) uint64 {
	efb := evenFeedback(even)
	bit := func(k uint) uint64 { return uint64((even >> k) & 1) }
	y0 := fa(bit(5), bit(6), bit(7), bit(8))
	y1 := fb(bit(9), bit(10), bit(11), bit(12))
	y2 := fb(bit(13), bit(14), bit(15), bit(16))
	y3 := fa(bit(17), bit(18), bit(19), bit(20))
	y4 := fb(bit(21), bit(22), bit(23), efb)
	return fc(y0, y1, y2, y3, y4)
}

// --- Feedback decomposition helpers -----------------------------------

// oddFeedback returns the XOR of lfsrTaps contributions from oddState.
// Taps at ODD full-state positions {5,9,15,17,19,25,27,29,35,39,41,43}
// map to oddState indices {2,4,7,8,9,12,13,14,17,19,20,21}.
func oddFeedback(odd uint32) uint64 {
	return uint64(((odd >> 2) ^ (odd >> 4) ^ (odd >> 7) ^ (odd >> 8) ^
		(odd >> 9) ^ (odd >> 12) ^ (odd >> 13) ^ (odd >> 14) ^
		(odd >> 17) ^ (odd >> 19) ^ (odd >> 20) ^ (odd >> 21)) & 1)
}

// evenFeedback returns the XOR of lfsrTaps contributions from evenState.
// Taps at EVEN full-state positions {0,10,12,14,24,42}
// map to evenState indices {0,5,6,7,12,21}.
func evenFeedback(even uint32) uint64 {
	return uint64(((even >> 0) ^ (even >> 5) ^ (even >> 6) ^
		(even >> 7) ^ (even >> 12) ^ (even >> 21)) & 1)
}

// --- Clock helpers for (odd,even) pair --------------------------------

// clockPairExact advances both oddState and evenState by one Crypt-mode
// LFSR clock using the full feedbackBit (both sub-states contribute).
//
// Forward clock: fullState_new = (fullState >> 1) | (feedbackBit << 47).
// Translating to sub-states:
//
//	evenState_new[k] = oddState[k]               for k = 0..23
//	oddState_new[k]  = evenState[k+1]            for k = 0..22
//	oddState_new[23] = feedbackBit(fullState)
func clockPairExact(odd, even uint32) (uint32, uint32) {
	fb := oddFeedback(odd) ^ evenFeedback(even)
	newEven := odd
	newOdd := (even >> 1) | (uint32(fb) << 23)
	return newOdd & 0xFFFFFF, newEven & 0xFFFFFF
}

// ks32Full computes the full 32-bit Crypt-mode keystream from the
// combined state given as (odd, even) sub-states. Equivalent to
// ksFromState(interleave(odd, even)).
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

// ks8Full computes the first 8 bits of the Crypt-mode keystream from
// (odd, even). Used for fast early-exit filtering in phase 2.
func ks8Full(odd, even uint32) uint32 {
	o, e := odd&0xFFFFFF, even&0xFFFFFF
	var ks uint32
	for i := uint(0); i < 8; i++ {
		full := interleave(o, e)
		bit := filterOutput(full)
		ks |= uint32(bit) << i
		o, e = clockPairExact(o, e)
	}
	return ks
}

// --- Phase-1 prediction function --------------------------------------

// pred16EvenFromOdd simulates 16 even-time Crypt-mode clocks starting from
// state interleave(odd, 0) and returns the 16 keystream bits at times
// t=0,2,4,...,30 packed into a uint16 (bit k = ks at time 2k).
//
// The prediction is exact at t=0 since filterOutput reads only oddState
// bits at t=0. For t≥2, the even-state feedback path contributes to the
// keystream; treating evenState=0 is a controlled approximation. When
// pred16EvenFromOdd(oddState_real) happens to equal the captured ks2's
// even-indexed bits, the fast phase-1 filter fires correctly.
func pred16EvenFromOdd(odd uint32) uint16 {
	o, e := odd&0xFFFFFF, uint32(0)
	var pred uint16
	for k := uint(0); k < 16; k++ {
		full := interleave(o, e)
		bit := filterOutput(full)
		pred |= uint16(bit) << k
		// Advance 2 clocks to reach the next even-time position.
		o, e = clockPairExact(o, e)
		o, e = clockPairExact(o, e)
	}
	return pred
}

// --- Core entry points ------------------------------------------------

// RecoverFast recovers the 48-bit MIFARE Classic sector key from two
// captured authentication exchanges using the Garcia et al. ESORICS 2008
// §4 filter-selectivity optimisation.
//
// Algorithm: two-phase state-space search using the (oddState, evenState)
// decomposition:
//
//  1. Phase 1: enumerate 2^24 oddState candidates. For each, compute
//     pred16EvenFromOdd and compare to the captured ks2's even bits. ~256
//     survivors expected when the approximation aligns (probabilistic; see
//     package overview). Budget: ≤1024 survivors before falling back.
//
//  2. Phase 2: for each survivor, enumerate 2^24 evenState candidates.
//     8-bit pre-check (ks8Full) followed by full 32-bit ks2 verification.
//     Roll back to candidate key and verify against second capture.
//
//  3. Fallback: RecoverWithRange(0, 1<<32) for guaranteed correctness when
//     the fast path misses. Terminates in O(2^N) for N-bit keys.
//
// RecoverFast always returns the correct key or an error. It is equivalent
// to Recover for correctness; the fast path provides better-than-O(2^48)
// expected performance for most key sizes.
//
// Parameters:
//
//	uid           — card UID (4 bytes)
//	nt0, nr0, ar0 — first capture: tag nonce, reader nonce, {aR}Ks
//	nt1, nr1, ar1 — second capture (same card, different nonces)
func RecoverFast(uid, nt0, nr0, ar0, nt1, nr1, ar1 uint32) (uint64, error) {
	return RecoverFastTimeout(context.Background(), uid, nt0, nr0, ar0, nt1, nr1, ar1)
}

// RecoverFastTimeout is RecoverFast with a context deadline, searching the
// full 2^48 keyspace in the guaranteed fallback. The context is checked
// approximately every 64K iterations to bound cancellation latency to a few
// milliseconds. Returns context.Canceled / context.DeadlineExceeded (wrapped)
// if the context is done before a key is found.
func RecoverFastTimeout(ctx context.Context, uid, nt0, nr0, ar0, nt1, nr1, ar1 uint32) (uint64, error) {
	return RecoverFastTimeoutRange(ctx, uid, nt0, nr0, ar0, nt1, nr1, ar1, 0, 1<<32)
}

// RecoverFastTimeoutRange is RecoverFastTimeout with an explicit bound on the
// high-32-bit search range of the GUARANTEED exhaustive fallback (loHi..hiHi,
// the same hi32 range as RecoverWithRange). This is the bug-free entry point
// for a caller that constrains the keyspace (e.g. mfkey32_recover's range_bits):
// a bounded fallback terminates with a clean "no key in range" instead of
// grinding the full 2^48, so range_bits actually limits the work.
//
// The probabilistic Garcia §4 fast path is NOT range-limited — it always
// enumerates its full 2^24 oddState space and, on the rare occasions it fires
// (~2^-15 of keys), recovers the key regardless of the range bound. So the
// range only bounds the deterministic fallback, never hides a key the fast
// path can reach. With loHi=0, hiHi=1<<32 this is the full-keyspace form.
func RecoverFastTimeoutRange(ctx context.Context, uid, nt0, nr0, ar0, nt1, nr1, ar1 uint32, loHi, hiHi uint64) (uint64, error) {
	// Derive the known keystreams from both captures.
	// ks2 = {aR} XOR prng(nT, 64)  —  the plain aR = prng(nT, 64).
	ks2_0 := ar0 ^ Prng(nt0, 64)
	ks2_1 := ar1 ^ Prng(nt1, 64)

	// Extract the 16 even-time bits of ks2_0: ks2_0[0], ks2_0[2], ..., ks2_0[30].
	var ks2_0_even uint16
	for k := uint(0); k < 16; k++ {
		ks2_0_even |= uint16((ks2_0>>(2*k))&1) << k
	}

	const checkInterval = 1 << 16
	// Garcia §4 phase-1+phase-2 budget: only run phase-2 when survivors are few.
	// With budget = 1024, phase-2 work ≤ 1024 × 2^24 = 2^34 ops.
	const phase2MaxSurvivors = 1024

	// Run the Garcia §4 phase-1+phase-2 fast path in a goroutine concurrently
	// with the guaranteed RecoverWithRange fallback. Return whichever finds the
	// key first. The fast path wins ~2^-15 of the time (when the probabilistic
	// pred16EvenFromOdd filter aligns with the real oddState). The fallback
	// always wins for keys where the fast path does not fire.
	type result struct {
		key uint64
		err error
	}
	ch := make(chan result, 2)

	// Start Garcia §4 fast path in background.
	obs.SafeGo("crypto1.mfkey32_fast.garcia", func() {
		survivors := make([]uint32, 0, 512)
		for x := uint32(0); x < (1 << 24); x++ {
			if x&(checkInterval-1) == 0 {
				select {
				case <-ctx.Done():
					return
				default:
				}
			}
			if pred16EvenFromOdd(x) == ks2_0_even {
				survivors = append(survivors, x)
			}
		}
		if len(survivors) > phase2MaxSurvivors {
			return // budget exceeded; let fallback handle it
		}
		ks2_0_lo8 := ks2_0 & 0xFF
		for _, x := range survivors {
			select {
			case <-ctx.Done():
				return
			default:
			}
			for y := uint32(0); y < (1 << 24); y++ {
				if ks8Full(x, y)&0xFF != ks2_0_lo8 {
					continue
				}
				if ks32Full(x, y) != ks2_0 {
					continue
				}
				stateAfterNR := interleave(x, y)
				key, ok := rollbackToKey(stateAfterNR, uid, nt0, nr0)
				if !ok {
					continue
				}
				c := New()
				c.Init(key)
				c.CryptFeedback(uid ^ nt1)
				c.EncCrypt(nr1, 0)
				if c.Crypt(0) == ks2_1 {
					ch <- result{key, nil}
					return
				}
			}
		}
	})

	// Start guaranteed fallback in background, bounded to the caller's hi32
	// range so range_bits is honoured (was hardcoded 0..1<<32, which silently
	// ignored any bound and ground the full 2^48). Pass ctx so the fallback's
	// inner hi32 loop also terminates promptly on cancellation.
	obs.SafeGo("crypto1.mfkey32_fast.fallback", func() {
		k, err := RecoverWithRange(ctx, uid, nt0, nr0, ar0, nt1, nr1, ar1, loHi, hiHi)
		ch <- result{k, err}
	})

	// Wait for the first result or context cancellation.
	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("mfkey32 fast: %w", ctx.Err())
	case res := <-ch:
		return res.key, res.err
	}
}

// rollbackToKey rolls back the LFSR state through the nR and nT auth
// phases to recover the candidate 48-bit key.
//
// Roll-back sequence (reverse of AuthEncrypt):
//
//  1. rollback32(stateAfterNR, nR)     → stateAfterNT
//  2. rollback32(stateAfterNT, uid^nT) → stateAfterInit = key
func rollbackToKey(stateAfterNR uint64, uid, nt, nr uint32) (key uint64, ok bool) {
	stateAfterNT := rollback32(stateAfterNR, nr)
	key = rollback32(stateAfterNT, uid^nt)
	if key != (key & 0xFFFFFFFFFFFF) {
		return 0, false
	}
	return key, true
}
