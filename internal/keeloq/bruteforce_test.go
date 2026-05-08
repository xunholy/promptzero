// SPDX-License-Identifier: AGPL-3.0-or-later

package keeloq

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// BruteForce correctness tests
// ---------------------------------------------------------------------------

// TestBruteForceFindsKey verifies that BruteForce recovers a key that lies
// within the search window. The key 0x00_AB_CD (decimal 44,237) is within
// [0, 2^20), making the test complete in well under a second on any CPU.
func TestBruteForceFindsKey(t *testing.T) {
	const (
		targetKey = uint64(0x00ABCD) // within 2^20
		pt        = uint32(0xDEADBEEF)
	)
	ct := Encrypt(pt, targetKey)

	found, ok, err := BruteForce(context.Background(), BruteForceConfig{
		KnownPlaintext:  pt,
		KnownCiphertext: ct,
		KeyspaceMin:     0,
		KeyspaceMax:     1 << 20,
		Workers:         2,
	})
	if err != nil {
		t.Fatalf("BruteForce returned unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("BruteForce failed to find key 0x%016X within [0, 2^20)", targetKey)
	}
	if found != targetKey {
		t.Fatalf("BruteForce found wrong key: got 0x%016X, want 0x%016X", found, targetKey)
	}
	// Double-check: the returned key must actually encrypt correctly.
	if Encrypt(pt, found) != ct {
		t.Fatalf("returned key 0x%016X does not reproduce ciphertext", found)
	}
}

// TestBruteForceExhausted verifies that BruteForce returns (0, false, nil)
// when the correct key is outside the search window.
func TestBruteForceExhausted(t *testing.T) {
	const (
		targetKey = uint64(0x1FFFFF) // just past our 2^20 search window
		pt        = uint32(0x12345678)
	)
	ct := Encrypt(pt, targetKey)

	_, ok, err := BruteForce(context.Background(), BruteForceConfig{
		KnownPlaintext:  pt,
		KnownCiphertext: ct,
		KeyspaceMin:     0,
		KeyspaceMax:     1 << 20,
		Workers:         2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("BruteForce unexpectedly found a key when the target was outside the window")
	}
}

// TestBruteForceEmptyRange exercises the fast-path for an empty keyspace.
func TestBruteForceEmptyRange(t *testing.T) {
	_, ok, err := BruteForce(context.Background(), BruteForceConfig{
		KnownPlaintext:  0,
		KnownCiphertext: 0,
		KeyspaceMin:     100,
		KeyspaceMax:     100, // empty range
		Workers:         1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatalf("expected false for empty range")
	}
}

// TestBruteForceZeroWorkers verifies that Workers=0 defaults to runtime.NumCPU().
// We just check it doesn't panic or deadlock.
func TestBruteForceZeroWorkers(t *testing.T) {
	const pt = uint32(0xABCD)
	const key = uint64(0x0000FF) // within 2^20
	ct := Encrypt(pt, key)

	_, ok, err := BruteForce(context.Background(), BruteForceConfig{
		KnownPlaintext:  pt,
		KnownCiphertext: ct,
		KeyspaceMin:     0,
		KeyspaceMax:     1 << 20,
		Workers:         0, // use runtime.NumCPU()
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected to find key 0x%016X", key)
	}
}

// TestBruteForceWorkersClampedAboveCap pins the upper-bound clamp.
// Without the cap a caller asking for Workers=10000 would spawn
// 10000 goroutines for a CPU-bound loop that saturates well
// below NumCPU. Run a tiny brute force with an absurd Workers
// value and confirm the call still returns correctly within a
// reasonable wall-clock budget — the goroutine spawn count is
// silently bounded by maxBruteForceWorkers (64).
func TestBruteForceWorkersClampedAboveCap(t *testing.T) {
	const pt = uint32(0xABCD)
	const key = uint64(0x0000FF)
	ct := Encrypt(pt, key)

	start := time.Now()
	_, ok, err := BruteForce(context.Background(), BruteForceConfig{
		KnownPlaintext:  pt,
		KnownCiphertext: ct,
		KeyspaceMin:     0,
		KeyspaceMax:     1 << 20,
		Workers:         10000, // would be 10000 goroutines without the clamp
	})
	if err != nil {
		t.Fatalf("BruteForce: %v", err)
	}
	if !ok {
		t.Fatalf("expected to find key 0x%016X", key)
	}
	// 64 workers on a 1<<20 keyspace returns in well under a
	// second on any reasonable host. Generous budget; the test
	// fails only if the clamp didn't fire and the runtime drowned
	// in goroutine spawn cost.
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("BruteForce took %v with workers=10000; clamp likely not effective", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Context cancellation test
// ---------------------------------------------------------------------------

// TestBruteForceCancellation launches BruteForce over a large window,
// cancels via context after 100ms, and asserts it returns within 500ms
// with ctx.Err() and no panic.
func TestBruteForceCancellation(t *testing.T) {
	// Any plaintext — we don't expect to find the key within the window before
	// the cancellation fires.
	const pt = uint32(0x11223344)
	ct := Encrypt(pt, 0xFFFFFFFFFFFFFFFF) // key is at the very end of 2^64

	ctx, cancel := context.WithCancel(context.Background())

	start := time.Now()
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	_, _, err := BruteForce(ctx, BruteForceConfig{
		KnownPlaintext:  pt,
		KnownCiphertext: ct,
		KeyspaceMin:     0,
		KeyspaceMax:     1 << 40, // deliberately huge — cannot be exhausted
		Workers:         2,
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected a context cancellation error, got nil")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("BruteForce took %v after cancel — expected <500ms", elapsed)
	}
}

// ---------------------------------------------------------------------------
// Progress callback test
// ---------------------------------------------------------------------------

// TestBruteForceProgress verifies that the Progress callback is invoked at
// least once for a search window that exceeds the internal progress interval
// (~1M keys). The window is set to 1<<20 + 1<<14 (just over the threshold).
// This test is skipped in -short mode because it takes ~5s under the race
// detector.
func TestBruteForceProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping progress test in -short mode (slow under race detector)")
	}

	const pt = uint32(0xFEDCBA)
	// Use a key beyond the window so we exhaust the range without an early exit.
	ct := Encrypt(pt, 0xDEAD0000) // key well beyond search window

	var calls atomic.Uint64
	_, _, err := BruteForce(context.Background(), BruteForceConfig{
		KnownPlaintext:  pt,
		KnownCiphertext: ct,
		KeyspaceMin:     0,
		KeyspaceMax:     (1 << 20) + (1 << 14), // slightly more than progressInterval
		Workers:         1,
		Progress: func(tried, total uint64) {
			calls.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls.Load() == 0 {
		t.Fatal("Progress callback was never called over a >1M key search")
	}
}

// ---------------------------------------------------------------------------
// Dictionary / manufacturer key tests
// ---------------------------------------------------------------------------

// TestTryDictionaryHit verifies that TryDictionary returns the correct entry
// when the plaintext+ciphertext pair was encrypted with one of the Known keys.
func TestTryDictionaryHit(t *testing.T) {
	for _, mk := range Known {
		pt := uint32(0x12345678)
		ct := Encrypt(pt, mk.Key)
		got, ok := TryDictionary(pt, ct)
		if !ok {
			t.Errorf("TryDictionary missed known key for vendor %q", mk.Vendor)
			continue
		}
		if got.Key != mk.Key {
			t.Errorf("TryDictionary returned wrong key for %q: got 0x%016X, want 0x%016X",
				mk.Vendor, got.Key, mk.Key)
		}
	}
}

// TestTryDictionaryMiss verifies that TryDictionary returns false when no
// Known entry matches. We use a key (0xBADC0FFEE0DDF00D) chosen to be
// absent from the Known table.
func TestTryDictionaryMiss(t *testing.T) {
	const unknownKey = uint64(0xBADC0FFEE0DDF00D)
	// Sanity: confirm the key is not in the table.
	for _, mk := range Known {
		if mk.Key == unknownKey {
			t.Fatalf("test key 0x%016X accidentally appears in Known table; update the test constant", unknownKey)
		}
	}

	pt := uint32(0xABCDEF01)
	ct := Encrypt(pt, unknownKey)

	_, ok := TryDictionary(pt, ct)
	if ok {
		t.Fatal("TryDictionary returned a hit for a key not in the Known table")
	}
}

// TestKnownTableNonEmpty guards against accidental truncation of the table.
func TestKnownTableNonEmpty(t *testing.T) {
	if len(Known) < 5 {
		t.Fatalf("Known manufacturer key table has only %d entries, expected >= 5", len(Known))
	}
}

// ---------------------------------------------------------------------------
// Speed benchmark (skipped in short mode)
// ---------------------------------------------------------------------------

// BenchmarkEncrypt measures raw encryption throughput. Typical result on
// a modern CPU: ~15–30 million encryptions per second per goroutine.
func BenchmarkEncrypt(b *testing.B) {
	key := uint64(0x0123456789ABCDEF)
	pt := uint32(0xDEADBEEF)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Encrypt(pt^uint32(i), key)
	}
}

// BenchmarkBruteForce2pow20 measures brute-force throughput over 2^20 keys.
func BenchmarkBruteForce2pow20(b *testing.B) {
	const pt = uint32(0xDEADBEEF)
	const key = uint64(0x00ABCD)
	ct := Encrypt(pt, key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = BruteForce(context.Background(), BruteForceConfig{
			KnownPlaintext:  pt,
			KnownCiphertext: ct,
			KeyspaceMin:     0,
			KeyspaceMax:     1 << 20,
			Workers:         1,
		})
	}
}
