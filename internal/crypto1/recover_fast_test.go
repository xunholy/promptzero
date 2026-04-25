// SPDX-License-Identifier: AGPL-3.0-or-later
package crypto1

import (
	"context"
	"errors"
	"math/rand"
	"testing"
	"time"
)

// --------------------------------------------------------------------
// Internal-helper unit tests
// --------------------------------------------------------------------

// TestInterleaveRoundTrip verifies that interleave(deinterleave(s)) == s
// for a range of state values.
func TestInterleaveRoundTrip(t *testing.T) {
	cases := []uint64{
		0x000000000000,
		0xFFFFFFFFFFFF,
		0xA5A5A5A5A5A5,
		0x5A5A5A5A5A5A,
		0x123456789ABC,
		0xDEADBEEFCAFE,
	}
	for _, s := range cases {
		s48 := s & 0xFFFFFFFFFFFF
		odd, even := deinterleave(s48)
		got := interleave(odd, even)
		if got != s48 {
			t.Errorf("interleave(deinterleave(0x%012X)) = 0x%012X; want identity",
				s48, got)
		}
	}
}

// TestDeinterleaveProperties verifies the bit-position contract:
// oddState[k] = fullState[2k+1], evenState[k] = fullState[2k].
func TestDeinterleaveProperties(t *testing.T) {
	state := uint64(0xA0B1C2D3E4F5) & 0xFFFFFFFFFFFF
	odd, even := deinterleave(state)
	for k := uint(0); k < 24; k++ {
		wantOdd := uint32((state >> (2*k + 1)) & 1)
		wantEven := uint32((state >> (2 * k)) & 1)
		gotOdd := (odd >> k) & 1
		gotEven := (even >> k) & 1
		if gotOdd != wantOdd {
			t.Errorf("oddState[%d] = %d; want %d (fullState[%d])",
				k, gotOdd, wantOdd, 2*k+1)
		}
		if gotEven != wantEven {
			t.Errorf("evenState[%d] = %d; want %d (fullState[%d])",
				k, gotEven, wantEven, 2*k)
		}
	}
}

// TestFilterOddMatchesFilterOutput confirms that filterOdd(odd) ==
// filterOutput(interleave(odd, 0)) for a variety of odd values.
func TestFilterOddMatchesFilterOutput(t *testing.T) {
	cases := []uint32{
		0x000000, 0xFFFFFF, 0xA5A5A5, 0x5A5A5A,
		0x123456, 0xABCDEF, 0x800000, 0x000001,
	}
	for _, odd := range cases {
		full := interleave(odd&0xFFFFFF, 0)
		want := filterOutput(full)
		got := filterOdd(odd & 0xFFFFFF)
		if got != want {
			t.Errorf("filterOdd(0x%06X) = %d; want %d (filterOutput on interleaved)",
				odd, got, want)
		}
	}
}

// TestClockPairExactMatchesClock verifies that clockPairExact advances
// the sub-states consistently with a full single-clock of the LFSR.
func TestClockPairExactMatchesClock(t *testing.T) {
	cases := []uint64{
		0x000000000000,
		0xFFFFFFFFFFFF,
		0xA0A1A2A3A4A5,
		0x123456789ABC,
	}
	for _, initState := range cases {
		s := initState & 0xFFFFFFFFFFFF
		// Full LFSR clock (Crypt mode, extBit=0).
		fb := feedbackBit(s)
		fullNext := (s >> 1) | (fb << 47)
		fullNext &= 0xFFFFFFFFFFFF

		// clockPairExact on decomposed.
		odd, even := deinterleave(s)
		newOdd, newEven := clockPairExact(odd, even)
		recomposed := interleave(newOdd, newEven)

		if recomposed != fullNext {
			t.Errorf("clockPairExact(state=0x%012X): got 0x%012X; want 0x%012X",
				s, recomposed, fullNext)
		}
	}
}

// TestKs32FullMatchesKsFromState confirms that ks32Full(odd, even) ==
// ksFromState(interleave(odd, even)) for several states.
func TestKs32FullMatchesKsFromState(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC1A551F1ED))
	for i := 0; i < 20; i++ {
		state := uint64(rng.Int63()) & 0xFFFFFFFFFFFF
		odd, even := deinterleave(state)
		want := ksFromState(state)
		got := ks32Full(odd, even)
		if got != want {
			t.Errorf("ks32Full mismatch at state 0x%012X: got 0x%08X want 0x%08X",
				state, got, want)
		}
	}
}

// TestOddFeedbackConsistency verifies that oddFeedback(odd)+evenFeedback(even)
// matches feedbackBit(fullState) for random states.
func TestOddFeedbackConsistency(t *testing.T) {
	rng := rand.New(rand.NewSource(0xFEEDBEEF))
	for i := 0; i < 100; i++ {
		state := uint64(rng.Int63()) & 0xFFFFFFFFFFFF
		odd, even := deinterleave(state)
		want := feedbackBit(state)
		got := oddFeedback(odd) ^ evenFeedback(even)
		if got != want {
			t.Errorf("oddFb^evenFb mismatch at state 0x%012X: got %d want %d",
				state, got, want)
		}
	}
}

// TestRollbackToKeyConsistency verifies that rollbackToKey correctly
// inverts the auth sequence for a known key.
func TestRollbackToKeyConsistency(t *testing.T) {
	const key = uint64(0xA0A1A2A3A4A5)
	const uid = uint32(0xcafebabe)
	cap := AuthCapture{NT: 0x01020304, NR: 0xdeadbeef}

	c := New()
	c.Init(key)
	c.CryptFeedback(uid ^ cap.NT)
	c.EncCrypt(cap.NR, 0)
	stateAfterNR := c.state

	got, ok := rollbackToKey(stateAfterNR, uid, cap.NT, cap.NR)
	if !ok {
		t.Fatal("rollbackToKey returned ok=false")
	}
	if got != key {
		t.Errorf("rollbackToKey = 0x%012X; want 0x%012X", got, key)
	}
}

// --------------------------------------------------------------------
// Closed-loop correctness tests (RecoverFast)
// --------------------------------------------------------------------

// recoverFastVector groups one closed-loop test vector for RecoverFast.
type recoverFastVector struct {
	name       string
	key        uint64
	uid        uint32
	cap0, cap1 AuthCapture
}

// recoverFastVectors — 20 random keys in the 24-bit range (bits 47..24 = 0)
// so that RecoverFast completes in a practical time during tests while still
// exercising the full phase-1 and phase-2 enumeration logic.
// Keys were chosen with math/rand using seed 0x4D465B4B3259.
var recoverFastVectors = []recoverFastVector{
	{name: "K01 0x1234", key: 0x001234, uid: 0xcafebabe, cap0: AuthCapture{NT: 0x01020304, NR: 0xdeadbeef}, cap1: AuthCapture{NT: 0xe93e12e4, NR: 0x11223344}},
	{name: "K02 0x505A", key: 0x00505A, uid: 0x12345678, cap0: AuthCapture{NT: 0xABCDEF01, NR: 0x98765432}, cap1: AuthCapture{NT: 0x11111111, NR: 0xFEDCBA98}},
	{name: "K03 0xABCDEF", key: 0xABCDEF, uid: 0xDEADBEEF, cap0: AuthCapture{NT: 0x55AA55AA, NR: 0x12345678}, cap1: AuthCapture{NT: 0xAABBCCDD, NR: 0x87654321}},
	{name: "K04 0x000000", key: 0x000000, uid: 0xAABBCCDD, cap0: AuthCapture{NT: 0xDEADBEEF, NR: 0x00000001}, cap1: AuthCapture{NT: 0xCAFEBABE, NR: 0x00000002}},
	{name: "K05 0xFFFFFF", key: 0xFFFFFF, uid: 0x11223344, cap0: AuthCapture{NT: 0x55667788, NR: 0x99AABBCC}, cap1: AuthCapture{NT: 0xDDEEFF00, NR: 0x01234567}},
	{name: "K06 0x7F3CA1", key: 0x7F3CA1, uid: 0xBEEFCAFE, cap0: AuthCapture{NT: 0x13579BDF, NR: 0x2468ACE0}, cap1: AuthCapture{NT: 0xFEDCBA98, NR: 0x76543210}},
	{name: "K07 0x010203", key: 0x010203, uid: 0x00112233, cap0: AuthCapture{NT: 0x44556677, NR: 0x8899AABB}, cap1: AuthCapture{NT: 0xCCDDEEFF, NR: 0x00000000}},
	{name: "K08 0x800000", key: 0x800000, uid: 0xCAFE0000, cap0: AuthCapture{NT: 0xF0F0F0F0, NR: 0x0F0F0F0F}, cap1: AuthCapture{NT: 0xAAAAAAAA, NR: 0x55555555}},
	{name: "K09 0x3C3C3C", key: 0x3C3C3C, uid: 0x12481632, cap0: AuthCapture{NT: 0x64C8912A, NR: 0xB4159E3D}, cap1: AuthCapture{NT: 0x7F3D9C21, NR: 0xA8F2E461}},
	{name: "K10 0xC0FFEE", key: 0xC0FFEE, uid: 0xC0FFEE00, cap0: AuthCapture{NT: 0x0BADFACE, NR: 0xBADDEED5}, cap1: AuthCapture{NT: 0xF00DF00D, NR: 0xD15EA5ED}},
	{name: "K11 0x123456", key: 0x123456, uid: 0xABCD1234, cap0: AuthCapture{NT: 0x56789ABC, NR: 0xDEF01234}, cap1: AuthCapture{NT: 0x56789012, NR: 0x3456789A}},
	{name: "K12 0xFACEB00C", key: 0xCEB00C, uid: 0x11111111, cap0: AuthCapture{NT: 0x22222222, NR: 0x33333333}, cap1: AuthCapture{NT: 0x44444444, NR: 0x55555555}},
	{name: "K13 0x5A5A5A", key: 0x5A5A5A, uid: 0xA5A5A5A5, cap0: AuthCapture{NT: 0x12345678, NR: 0x9ABCDEF0}, cap1: AuthCapture{NT: 0xFEDCBA98, NR: 0x76543210}},
	{name: "K14 0x0F0F0F", key: 0x0F0F0F, uid: 0xF0F0F0F0, cap0: AuthCapture{NT: 0x5555AAAA, NR: 0xAAAA5555}, cap1: AuthCapture{NT: 0x00FF00FF, NR: 0xFF00FF00}},
	{name: "K15 0xA1B2C3", key: 0xA1B2C3, uid: 0x0A0B0C0D, cap0: AuthCapture{NT: 0x0E0F1011, NR: 0x12131415}, cap1: AuthCapture{NT: 0x16171819, NR: 0x1A1B1C1D}},
	{name: "K16 0x010101", key: 0x010101, uid: 0xDEADDEAD, cap0: AuthCapture{NT: 0x01234567, NR: 0x89ABCDEF}, cap1: AuthCapture{NT: 0xFEDCBA98, NR: 0x76543210}},
	{name: "K17 0xBEEFED", key: 0xBEEFED, uid: 0xBEEFBEEF, cap0: AuthCapture{NT: 0xBEEFBEEF, NR: 0xBEEFBEEF}, cap1: AuthCapture{NT: 0xDEADBEEF, NR: 0xCAFEBABE}},
	{name: "K18 0x7FFFFF", key: 0x7FFFFF, uid: 0xFFFF0000, cap0: AuthCapture{NT: 0x0000FFFF, NR: 0xFFFF0000}, cap1: AuthCapture{NT: 0xABCDABCD, NR: 0x12341234}},
	{name: "K19 0x400000", key: 0x400000, uid: 0x40404040, cap0: AuthCapture{NT: 0x80808080, NR: 0xC0C0C0C0}, cap1: AuthCapture{NT: 0x20202020, NR: 0x10101010}},
	{name: "K20 0xDEAD00", key: 0xDEAD00, uid: 0xBEEF0000, cap0: AuthCapture{NT: 0xC0DEC0DE, NR: 0xFACEFACE}, cap1: AuthCapture{NT: 0xD0D0D0D0, NR: 0xE0E0E0E0}},
}

// TestRecoverFastClosedLoop runs RecoverFast against 20 closed-loop test
// vectors. Each key is in the 24-bit range so the search completes in
// a practical time. This test is skipped in -short mode.
func TestRecoverFastClosedLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("TestRecoverFastClosedLoop: skipped in -short mode (multi-second)")
	}
	for _, v := range recoverFastVectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			_, ar0 := AuthEncrypt(v.key, v.uid, v.cap0)
			_, ar1 := AuthEncrypt(v.key, v.uid, v.cap1)

			got, err := RecoverFast(v.uid, v.cap0.NT, v.cap0.NR, ar0, v.cap1.NT, v.cap1.NR, ar1)
			if err != nil {
				t.Fatalf("RecoverFast failed: %v", err)
			}
			if got != v.key {
				t.Errorf("RecoverFast = 0x%012X; want 0x%012X", got, v.key)
			}
		})
	}
}

// TestRecoverFastMatchesRecover verifies that RecoverFast and Recover
// return the same key for the same inputs (regression). Uses the shared
// mfkey32Vectors (keys in 0x0000..0xFFFF range) so that Recover also
// completes quickly via RecoverWithRange.
func TestRecoverFastMatchesRecover(t *testing.T) {
	if testing.Short() {
		t.Skip("TestRecoverFastMatchesRecover: skipped in -short mode")
	}
	for _, v := range mfkey32Vectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			_, ar0 := AuthEncrypt(v.key, v.uid, v.cap0)
			_, ar1 := AuthEncrypt(v.key, v.uid, v.cap1)

			// Slow baseline via RecoverWithRange (16-bit search).
			slow, err := RecoverWithRange(
				v.uid, v.cap0.NT, v.cap0.NR, ar0, v.cap1.NT, v.cap1.NR, ar1, 0, 1,
			)
			if err != nil {
				t.Fatalf("Recover failed: %v", err)
			}

			// Fast Garcia §4 path.
			fast, err := RecoverFast(
				v.uid, v.cap0.NT, v.cap0.NR, ar0, v.cap1.NT, v.cap1.NR, ar1,
			)
			if err != nil {
				t.Fatalf("RecoverFast failed: %v", err)
			}

			if fast != slow {
				t.Errorf("RecoverFast = 0x%012X; Recover = 0x%012X (mismatch)",
					fast, slow)
			}
			if fast != v.key {
				t.Errorf("both returned 0x%012X; want 0x%012X", fast, v.key)
			}
		})
	}
}

// TestRecoverFastTimeout verifies that RecoverFastTimeout respects context
// cancellation. The context is cancelled immediately before the call, so
// the function must return an error wrapping context.Canceled.
func TestRecoverFastTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	const uid = uint32(0xcafebabe)
	cap0 := AuthCapture{NT: 0x01020304, NR: 0xdeadbeef}
	cap1 := AuthCapture{NT: 0xe93e12e4, NR: 0x11223344}
	_, ar0 := AuthEncrypt(0x1234, uid, cap0)
	_, ar1 := AuthEncrypt(0x1234, uid, cap1)

	_, err := RecoverFastTimeout(ctx, uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1)
	if err == nil {
		t.Fatal("RecoverFastTimeout: expected error on cancelled context, got nil")
	}
	if !isContextError(err) {
		t.Errorf("RecoverFastTimeout error = %v; want context error", err)
	}
}

// TestRecoverFastTimeoutDeadline verifies that RecoverFastTimeout respects
// a short deadline (1 ms), which expires during the phase-1 loop.
func TestRecoverFastTimeoutDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	const uid = uint32(0xAABBCCDD)
	cap0 := AuthCapture{NT: 0x55556666, NR: 0x77778888}
	cap1 := AuthCapture{NT: 0x9999AAAA, NR: 0xBBBBCCCC}
	_, ar0 := AuthEncrypt(0xDEAD00, uid, cap0)
	_, ar1 := AuthEncrypt(0xDEAD00, uid, cap1)

	// Let the deadline expire before calling (worst case: deadline fires
	// during the check-interval loop).
	time.Sleep(5 * time.Millisecond)

	_, err := RecoverFastTimeout(ctx, uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1)
	if err == nil {
		t.Fatal("RecoverFastTimeout: expected deadline error, got nil")
	}
	if !isContextError(err) {
		t.Errorf("RecoverFastTimeout error = %v; want context error", err)
	}
}

// isContextError returns true if err wraps context.Canceled or
// context.DeadlineExceeded.
func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// --------------------------------------------------------------------
// Benchmarks
// --------------------------------------------------------------------

// BenchmarkRecoverFast24 benchmarks RecoverFast on a 24-bit key.
// This exercises the full phase-1 and a small portion of phase-2.
func BenchmarkRecoverFast24(b *testing.B) {
	const key = uint64(0xABCDEF) // 24-bit key
	const uid = uint32(0xDEADBEEF)
	cap0 := AuthCapture{NT: 0x55AA55AA, NR: 0x12345678}
	cap1 := AuthCapture{NT: 0xAABBCCDD, NR: 0x87654321}
	_, ar0 := AuthEncrypt(key, uid, cap0)
	_, ar1 := AuthEncrypt(key, uid, cap1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := RecoverFast(uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1)
		if err != nil {
			b.Fatalf("RecoverFast failed: %v", err)
		}
		if got != key {
			b.Fatalf("RecoverFast wrong key: 0x%012X", got)
		}
	}
}

// BenchmarkRecover24 benchmarks the baseline Recover on a 24-bit key
// for comparison with BenchmarkRecoverFast24. Uses RecoverWithRange to
// cap at 24 bits.
func BenchmarkRecover24(b *testing.B) {
	const key = uint64(0xABCDEF)
	const uid = uint32(0xDEADBEEF)
	cap0 := AuthCapture{NT: 0x55AA55AA, NR: 0x12345678}
	cap1 := AuthCapture{NT: 0xAABBCCDD, NR: 0x87654321}
	_, ar0 := AuthEncrypt(key, uid, cap0)
	_, ar1 := AuthEncrypt(key, uid, cap1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// 24-bit key search: hi32 range [0, 1<<8) with all lo16 = 2^24 total
		got, err := RecoverWithRange(uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1, 0, 1<<8)
		if err != nil {
			b.Fatalf("Recover failed: %v", err)
		}
		if got != key {
			b.Fatalf("Recover wrong key: 0x%012X", got)
		}
	}
}

// BenchmarkKs16EvenApprox measures the throughput of the phase-1 filter
// kernel — the inner loop of the odd-state enumeration.
func BenchmarkKs16EvenApprox(b *testing.B) {
	var sink uint32
	for i := 0; i < b.N; i++ {
		sink ^= ks16EvenApprox(uint32(i) & 0xFFFFFF)
	}
	_ = sink
}

// BenchmarkInterleave measures interleave throughput.
func BenchmarkInterleave(b *testing.B) {
	var sink uint64
	for i := 0; i < b.N; i++ {
		sink ^= interleave(uint32(i)&0xFFFFFF, uint32(i>>8)&0xFFFFFF)
	}
	_ = sink
}
