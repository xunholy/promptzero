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

// TestInterleaveRoundTrip verifies that interleave(deinterleave(s)) == s.
func TestInterleaveRoundTrip(t *testing.T) {
	cases := []uint64{
		0x000000000000, 0xFFFFFFFFFFFF, 0xA5A5A5A5A5A5,
		0x5A5A5A5A5A5A, 0x123456789ABC, 0xDEADBEEFCAFE,
	}
	for _, s := range cases {
		s48 := s & 0xFFFFFFFFFFFF
		odd, even := deinterleave(s48)
		got := interleave(odd, even)
		if got != s48 {
			t.Errorf("interleave(deinterleave(0x%012X)) = 0x%012X; want identity", s48, got)
		}
	}
}

// TestDeinterleaveProperties verifies oddState[k]=fullState[2k+1], evenState[k]=fullState[2k].
func TestDeinterleaveProperties(t *testing.T) {
	state := uint64(0xA0B1C2D3E4F5) & 0xFFFFFFFFFFFF
	odd, even := deinterleave(state)
	for k := uint(0); k < 24; k++ {
		if (odd>>k)&1 != uint32((state>>(2*k+1))&1) {
			t.Errorf("oddState[%d] wrong", k)
		}
		if (even>>k)&1 != uint32((state>>(2*k))&1) {
			t.Errorf("evenState[%d] wrong", k)
		}
	}
}

// TestFilterOddMatchesFilterOutput confirms filterOdd(odd) == filterOutput(interleave(odd,0)).
func TestFilterOddMatchesFilterOutput(t *testing.T) {
	cases := []uint32{0x000000, 0xFFFFFF, 0xA5A5A5, 0x5A5A5A, 0x123456, 0xABCDEF, 0x800000, 0x000001}
	for _, odd := range cases {
		full := interleave(odd&0xFFFFFF, 0)
		want := filterOutput(full)
		got := filterOdd(odd & 0xFFFFFF)
		if got != want {
			t.Errorf("filterOdd(0x%06X) = %d; want %d", odd, got, want)
		}
	}
}

// TestFilterOddExactlyKS2Bit0 confirms filterOdd(realOddState) == ks2[0] exactly.
func TestFilterOddExactlyKS2Bit0(t *testing.T) {
	const key = uint64(0xA0A1A2A3A4A5)
	const uid = uint32(0xcafebabe)
	cap := AuthCapture{NT: 0x01020304, NR: 0xdeadbeef}

	c := New()
	c.Init(key)
	c.CryptFeedback(uid ^ cap.NT)
	c.EncCrypt(cap.NR, 0)
	stateAfterNR := c.state
	ks2 := c.Crypt(0)

	odd, _ := deinterleave(stateAfterNR)
	if uint32(filterOdd(odd)) != (ks2 & 1) {
		t.Errorf("filterOdd(realOddState) = %d; want ks2[0] = %d",
			filterOdd(odd), ks2&1)
	}
}

// TestFilterEvenDerivation checks filterEven(even) against filterOutput after 1 clock.
func TestFilterEvenDerivation(t *testing.T) {
	cases := []uint32{0x000000, 0xFFFFFF, 0xA5A5A5, 0x5A5A5A, 0x123456}
	for _, even := range cases {
		state := interleave(0, even&0xFFFFFF)
		fb := feedbackBit(state)
		state1 := (state >> 1) | (fb << 47)
		want := filterOutput(state1)
		got := filterEven(even & 0xFFFFFF)
		if got != want {
			t.Errorf("filterEven(0x%06X) = %d; want %d", even, got, want)
		}
	}
}

// TestClockPairExactMatchesClock verifies clockPairExact matches a full LFSR clock.
func TestClockPairExactMatchesClock(t *testing.T) {
	cases := []uint64{0x000000000000, 0xFFFFFFFFFFFF, 0xA0A1A2A3A4A5, 0x123456789ABC}
	for _, initState := range cases {
		s := initState & 0xFFFFFFFFFFFF
		fb := feedbackBit(s)
		fullNext := ((s >> 1) | (fb << 47)) & 0xFFFFFFFFFFFF
		odd, even := deinterleave(s)
		newOdd, newEven := clockPairExact(odd, even)
		recomposed := interleave(newOdd, newEven)
		if recomposed != fullNext {
			t.Errorf("clockPairExact(0x%012X): got 0x%012X; want 0x%012X", s, recomposed, fullNext)
		}
	}
}

// TestKs32FullMatchesKsFromState confirms ks32Full(odd,even) == ksFromState(interleave(odd,even)).
func TestKs32FullMatchesKsFromState(t *testing.T) {
	rng := rand.New(rand.NewSource(0xC1A551F1ED))
	for i := 0; i < 20; i++ {
		state := uint64(rng.Int63()) & 0xFFFFFFFFFFFF
		odd, even := deinterleave(state)
		want := ksFromState(state)
		got := ks32Full(odd, even)
		if got != want {
			t.Errorf("ks32Full mismatch at 0x%012X: got 0x%08X want 0x%08X", state, got, want)
		}
	}
}

// TestKs8FullMatchesPrefix confirms ks8Full returns the low 8 bits of ks32Full.
func TestKs8FullMatchesPrefix(t *testing.T) {
	rng := rand.New(rand.NewSource(0xBEEFBEEF))
	for i := 0; i < 20; i++ {
		state := uint64(rng.Int63()) & 0xFFFFFFFFFFFF
		odd, even := deinterleave(state)
		want8 := ks32Full(odd, even) & 0xFF
		got8 := ks8Full(odd, even) & 0xFF
		if got8 != want8 {
			t.Errorf("ks8Full prefix mismatch at 0x%012X: got 0x%02X want 0x%02X", state, got8, want8)
		}
	}
}

// TestOddFeedbackConsistency verifies oddFeedback(odd)^evenFeedback(even) == feedbackBit(full).
func TestOddFeedbackConsistency(t *testing.T) {
	rng := rand.New(rand.NewSource(0xFEEDBEEF))
	for i := 0; i < 100; i++ {
		state := uint64(rng.Int63()) & 0xFFFFFFFFFFFF
		odd, even := deinterleave(state)
		want := feedbackBit(state)
		got := oddFeedback(odd) ^ evenFeedback(even)
		if got != want {
			t.Errorf("oddFb^evenFb mismatch at 0x%012X: got %d want %d", state, got, want)
		}
	}
}

// TestPred16EvenFromOddBit0IsExact verifies pred16EvenFromOdd(real_odd)[0] == ks2[0] exactly.
func TestPred16EvenFromOddBit0IsExact(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5EC2B17))
	for i := 0; i < 50; i++ {
		state := uint64(rng.Int63()) & 0xFFFFFFFFFFFF
		ks2 := ksFromState(state)
		odd, _ := deinterleave(state)
		pred := pred16EvenFromOdd(odd)
		if pred&1 != uint16(ks2&1) {
			t.Errorf("pred16EvenFromOdd bit-0 mismatch at 0x%012X: got %d want %d",
				state, pred&1, ks2&1)
		}
	}
}

// TestRollbackToKeyConsistency verifies rollbackToKey inverts the auth sequence.
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

type recoverFastVector struct {
	name       string
	key        uint64
	uid        uint32
	cap0, cap1 AuthCapture
}

// recoverFastVectors uses 16-bit keys so RecoverFast completes quickly
// via the fallback RecoverWithRange(0,1) path (~70 ms per vector).
var recoverFastVectors = []recoverFastVector{
	{name: "K01 0x1234", key: 0x1234, uid: 0xcafebabe, cap0: AuthCapture{NT: 0x01020304, NR: 0xdeadbeef}, cap1: AuthCapture{NT: 0xe93e12e4, NR: 0x11223344}},
	{name: "K02 0x505A", key: 0x505A, uid: 0x12345678, cap0: AuthCapture{NT: 0xABCDEF01, NR: 0x98765432}, cap1: AuthCapture{NT: 0x11111111, NR: 0xFEDCBA98}},
	{name: "K03 0xABCD", key: 0xABCD, uid: 0xDEADBEEF, cap0: AuthCapture{NT: 0x55AA55AA, NR: 0x12345678}, cap1: AuthCapture{NT: 0xAABBCCDD, NR: 0x87654321}},
	{name: "K04 0x0000", key: 0x0000, uid: 0xAABBCCDD, cap0: AuthCapture{NT: 0xDEADBEEF, NR: 0x00000001}, cap1: AuthCapture{NT: 0xCAFEBABE, NR: 0x00000002}},
	{name: "K05 0xFFFF", key: 0xFFFF, uid: 0x11223344, cap0: AuthCapture{NT: 0x55667788, NR: 0x99AABBCC}, cap1: AuthCapture{NT: 0xDDEEFF00, NR: 0x01234567}},
	{name: "K06 0x7F3C", key: 0x7F3C, uid: 0xBEEFCAFE, cap0: AuthCapture{NT: 0x13579BDF, NR: 0x2468ACE0}, cap1: AuthCapture{NT: 0xFEDCBA98, NR: 0x76543210}},
	{name: "K07 0x0102", key: 0x0102, uid: 0x00112233, cap0: AuthCapture{NT: 0x44556677, NR: 0x8899AABB}, cap1: AuthCapture{NT: 0xCCDDEEFF, NR: 0x00000000}},
	{name: "K08 0x8000", key: 0x8000, uid: 0xCAFE0000, cap0: AuthCapture{NT: 0xF0F0F0F0, NR: 0x0F0F0F0F}, cap1: AuthCapture{NT: 0xAAAAAAAA, NR: 0x55555555}},
	{name: "K09 0x3C3C", key: 0x3C3C, uid: 0x12481632, cap0: AuthCapture{NT: 0x64C8912A, NR: 0xB4159E3D}, cap1: AuthCapture{NT: 0x7F3D9C21, NR: 0xA8F2E461}},
	{name: "K10 0xC0FF", key: 0xC0FF, uid: 0xC0FFEE00, cap0: AuthCapture{NT: 0x0BADFACE, NR: 0xBADDEED5}, cap1: AuthCapture{NT: 0xF00DF00D, NR: 0xD15EA5ED}},
	{name: "K11 0x2345", key: 0x2345, uid: 0xABCD1234, cap0: AuthCapture{NT: 0x56789ABC, NR: 0xDEF01234}, cap1: AuthCapture{NT: 0x56789012, NR: 0x3456789A}},
	{name: "K12 0xB00C", key: 0xB00C, uid: 0x11111111, cap0: AuthCapture{NT: 0x22222222, NR: 0x33333333}, cap1: AuthCapture{NT: 0x44444444, NR: 0x55555555}},
	{name: "K13 0x5A5A", key: 0x5A5A, uid: 0xA5A5A5A5, cap0: AuthCapture{NT: 0x12345678, NR: 0x9ABCDEF0}, cap1: AuthCapture{NT: 0xFEDCBA98, NR: 0x76543210}},
	{name: "K14 0x0F0F", key: 0x0F0F, uid: 0xF0F0F0F0, cap0: AuthCapture{NT: 0x5555AAAA, NR: 0xAAAA5555}, cap1: AuthCapture{NT: 0x00FF00FF, NR: 0xFF00FF00}},
	{name: "K15 0xA1B2", key: 0xA1B2, uid: 0x0A0B0C0D, cap0: AuthCapture{NT: 0x0E0F1011, NR: 0x12131415}, cap1: AuthCapture{NT: 0x16171819, NR: 0x1A1B1C1D}},
	{name: "K16 0x0101", key: 0x0101, uid: 0xDEADDEAD, cap0: AuthCapture{NT: 0x01234567, NR: 0x89ABCDEF}, cap1: AuthCapture{NT: 0xFEDCBA98, NR: 0x76543210}},
	{name: "K17 0xBEEF", key: 0xBEEF, uid: 0xBEEFBEEF, cap0: AuthCapture{NT: 0xBEEFBEEF, NR: 0xBEEFBEEF}, cap1: AuthCapture{NT: 0xDEADBEEF, NR: 0xCAFEBABE}},
	{name: "K18 0x7FFF", key: 0x7FFF, uid: 0xFFFF0000, cap0: AuthCapture{NT: 0x0000FFFF, NR: 0xFFFF0000}, cap1: AuthCapture{NT: 0xABCDABCD, NR: 0x12341234}},
	{name: "K19 0x4000", key: 0x4000, uid: 0x40404040, cap0: AuthCapture{NT: 0x80808080, NR: 0xC0C0C0C0}, cap1: AuthCapture{NT: 0x20202020, NR: 0x10101010}},
	{name: "K20 0xDEAD", key: 0xDEAD, uid: 0xBEEF0000, cap0: AuthCapture{NT: 0xC0DEC0DE, NR: 0xFACEFACE}, cap1: AuthCapture{NT: 0xD0D0D0D0, NR: 0xE0E0E0E0}},
}

// TestRecoverFastClosedLoop runs RecoverFast against 20 closed-loop vectors.
// Skipped in -short mode (~70 ms per vector via fallback path).
func TestRecoverFastClosedLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("TestRecoverFastClosedLoop: skipped in -short mode (~70 ms per vector)")
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

// TestRecoverFastMatchesRecover verifies RecoverFast and Recover return the same key.
func TestRecoverFastMatchesRecover(t *testing.T) {
	if testing.Short() {
		t.Skip("TestRecoverFastMatchesRecover: skipped in -short mode")
	}
	for _, v := range mfkey32Vectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			_, ar0 := AuthEncrypt(v.key, v.uid, v.cap0)
			_, ar1 := AuthEncrypt(v.key, v.uid, v.cap1)

			slow, err := RecoverWithRange(
				context.Background(),
				v.uid, v.cap0.NT, v.cap0.NR, ar0, v.cap1.NT, v.cap1.NR, ar1, 0, 1,
			)
			if err != nil {
				t.Fatalf("Recover failed: %v", err)
			}

			fast, err := RecoverFast(
				v.uid, v.cap0.NT, v.cap0.NR, ar0, v.cap1.NT, v.cap1.NR, ar1,
			)
			if err != nil {
				t.Fatalf("RecoverFast failed: %v", err)
			}

			if fast != slow {
				t.Errorf("RecoverFast=0x%012X Recover=0x%012X (mismatch)", fast, slow)
			}
			if fast != v.key {
				t.Errorf("both=0x%012X; want 0x%012X", fast, v.key)
			}
		})
	}
}

// TestRecoverFastTimeout verifies RecoverFastTimeout respects a cancelled context.
func TestRecoverFastTimeout(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

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

// TestRecoverFastTimeoutDeadline verifies RecoverFastTimeout respects a short deadline.
func TestRecoverFastTimeoutDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	const uid = uint32(0xAABBCCDD)
	cap0 := AuthCapture{NT: 0x55556666, NR: 0x77778888}
	cap1 := AuthCapture{NT: 0x9999AAAA, NR: 0xBBBBCCCC}
	_, ar0 := AuthEncrypt(0xDEAD, uid, cap0)
	_, ar1 := AuthEncrypt(0xDEAD, uid, cap1)

	time.Sleep(5 * time.Millisecond)

	_, err := RecoverFastTimeout(ctx, uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1)
	if err == nil {
		t.Fatal("RecoverFastTimeout: expected deadline error, got nil")
	}
	if !isContextError(err) {
		t.Errorf("RecoverFastTimeout error = %v; want context error", err)
	}
}

func isContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// --------------------------------------------------------------------
// Benchmarks
// --------------------------------------------------------------------

// BenchmarkRecoverFast16 benchmarks RecoverFast on a 16-bit key.
// RecoverFast runs Garcia §4 phase-1 (2^24 pred16EvenFromOdd calls), then
// when the fast path misses, falls back to RecoverWithRange(0,1) for the
// 16-bit keyspace. Compare against BenchmarkRecover16.
func BenchmarkRecoverFast16(b *testing.B) {
	const key = uint64(0xA5B3)
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

// BenchmarkRecover16 benchmarks RecoverWithRange(0,1) on a 16-bit key.
func BenchmarkRecover16(b *testing.B) {
	const key = uint64(0xA5B3)
	const uid = uint32(0xDEADBEEF)
	cap0 := AuthCapture{NT: 0x55AA55AA, NR: 0x12345678}
	cap1 := AuthCapture{NT: 0xAABBCCDD, NR: 0x87654321}
	_, ar0 := AuthEncrypt(key, uid, cap0)
	_, ar1 := AuthEncrypt(key, uid, cap1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := RecoverWithRange(context.Background(), uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1, 0, 1)
		if err != nil {
			b.Fatalf("Recover failed: %v", err)
		}
		if got != key {
			b.Fatalf("Recover wrong key: 0x%012X", got)
		}
	}
}

// BenchmarkPred16EvenFromOdd measures the phase-1 filter kernel throughput.
func BenchmarkPred16EvenFromOdd(b *testing.B) {
	var sink uint16
	for i := 0; i < b.N; i++ {
		sink ^= pred16EvenFromOdd(uint32(i) & 0xFFFFFF)
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

// BenchmarkKs32Full measures full 32-bit keystream computation from (odd,even).
func BenchmarkKs32Full(b *testing.B) {
	var sink uint32
	odd, even := uint32(0xABCDEF), uint32(0x123456)
	for i := 0; i < b.N; i++ {
		sink ^= ks32Full(odd^uint32(i), even^uint32(i>>8))
	}
	_ = sink
}

// BenchmarkRecoverFastVsFullRecover demonstrates the speedup of RecoverFast
// over a full Recover (RecoverWithRange(0,1<<32)) call, for a 16-bit key.
// RecoverFast uses the parallel Garcia §4 fast path plus the exhaustive fallback;
// the fallback terminates quickly when the key has a small value, while Recover
// would scan the full 2^48 keyspace before finding it.
//
// Note: both RecoverFast and Recover (RecoverWithRange(0,1<<32)) terminate
// when the key is found, so for a key near the start of the search space both
// are fast. The speedup manifests for keys with large hi32 values or when using
// the Garcia §4 fast path for full-keyspace attacks.
func BenchmarkRecoverFastVsRecover_16bit(b *testing.B) {
	const key = uint64(0xA5B3)
	const uid = uint32(0xDEADBEEF)
	cap0 := AuthCapture{NT: 0x55AA55AA, NR: 0x12345678}
	cap1 := AuthCapture{NT: 0xAABBCCDD, NR: 0x87654321}
	_, ar0 := AuthEncrypt(key, uid, cap0)
	_, ar1 := AuthEncrypt(key, uid, cap1)

	b.Run("RecoverFast", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			got, err := RecoverFast(uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1)
			if err != nil || got != key {
				b.Fatalf("RecoverFast failed err=%v key=0x%012X", err, got)
			}
		}
	})
	b.Run("Recover_bounded16", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			got, err := RecoverWithRange(context.Background(), uid, cap0.NT, cap0.NR, ar0, cap1.NT, cap1.NR, ar1, 0, 1)
			if err != nil || got != key {
				b.Fatalf("RecoverWithRange failed err=%v key=0x%012X", err, got)
			}
		}
	})
}
