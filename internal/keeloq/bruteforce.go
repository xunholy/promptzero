// SPDX-License-Identifier: AGPL-3.0-or-later

package keeloq

// This file implements a CPU-bound brute-force search over a KeeLoq keyspace.
//
// # Performance expectations
//
// A single modern CPU core can test roughly 10–30 million keys per second.
// Practical CPU limits for a multi-core workstation:
//
//   - ~2^28 keys: a few seconds
//   - ~2^32 keys: a few minutes (useful for 32-bit manufacturer-derived keys)
//   - ~2^36 keys: several hours (stretch limit)
//   - 2^64 keys: not feasible on CPU — use the GPU path (X-Stuff/CudaKeeloq)
//
// For production-scale exhaustive search against the full 2^64 KeeLoq keyspace,
// use CudaKeeloq (requires NVIDIA CUDA). This package's BruteForce function
// is intended for:
//
//  1. Educational demonstration and ground-truth comparison with the GPU path.
//  2. Dictionary-based searches (see TryDictionary in manufacturer.go).
//  3. Known-prefix / manufacturer-key-derivation searches where the effective
//     keyspace is 2^32 or smaller.

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
)

// BruteForceConfig configures a CPU brute-force key search.
type BruteForceConfig struct {
	// KnownPlaintext is a 32-bit plaintext believed to have been encrypted
	// under the target key.
	KnownPlaintext uint32

	// KnownCiphertext is the ciphertext corresponding to KnownPlaintext.
	KnownCiphertext uint32

	// KeyspaceMin is the inclusive lower bound of the search range.
	KeyspaceMin uint64

	// KeyspaceMax is the exclusive upper bound of the search range.
	// When KeyspaceMax <= KeyspaceMin the call returns immediately with
	// (0, false, nil).
	KeyspaceMax uint64

	// Workers is the number of goroutines to spawn. Zero means
	// runtime.NumCPU().
	Workers int

	// Progress is an optional callback invoked periodically (approximately
	// every 1 million attempts per worker). tried is the total keys tested
	// so far; total is KeyspaceMax - KeyspaceMin. May be called
	// concurrently from different workers.
	Progress func(tried, total uint64)
}

// cancelCheckInterval controls how often each worker checks for context
// cancellation and early exit (found flag). This is kept small so that the
// goroutines respond promptly even when running under the race detector (which
// reduces throughput ~10x). At ~2M keys/sec under the race detector, 8192
// iterations ≈ 4ms between checks.
const cancelCheckInterval = 1 << 13 // 8192 iterations

// progressInterval controls how often per-worker progress is aggregated and
// reported via the Progress callback. Must be a power-of-two multiple of
// cancelCheckInterval.
const progressInterval = 1 << 20 // ~1M keys per worker

// BruteForce searches the keyspace [cfg.KeyspaceMin, cfg.KeyspaceMax) for a
// key K such that Encrypt(cfg.KnownPlaintext, K) == cfg.KnownCiphertext.
// It returns the first matching key found, true, nil on success.
// When the keyspace is fully exhausted without a match it returns 0, false, nil.
// When ctx is cancelled it returns 0, false, ctx.Err().
//
// The search is sharded across cfg.Workers goroutines (default: runtime.NumCPU).
// Caller is responsible for choosing a realistic search range — see the package
// comment for CPU-feasibility guidance.
func BruteForce(ctx context.Context, cfg BruteForceConfig) (uint64, bool, error) {
	if cfg.KeyspaceMax <= cfg.KeyspaceMin {
		return 0, false, nil
	}

	workers := cfg.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	total := cfg.KeyspaceMax - cfg.KeyspaceMin
	span := total / uint64(workers)

	var (
		found    atomic.Uint64
		foundKey atomic.Uint64
		tried    atomic.Uint64
		once     sync.Once
		wg       sync.WaitGroup
	)

	reportProgress := func() {
		if cfg.Progress != nil {
			cfg.Progress(tried.Load(), total)
		}
	}

	for w := 0; w < workers; w++ {
		lo := cfg.KeyspaceMin + uint64(w)*span
		hi := lo + span
		if w == workers-1 {
			// last shard takes any remainder from integer division
			hi = cfg.KeyspaceMax
		}

		wg.Add(1)
		go func(lo, hi uint64) {
			defer wg.Done()
			localTried := uint64(0)
			progressAccum := uint64(0)

			for k := lo; k < hi; k++ {
				// Check cancellation and early-exit at small intervals so
				// the goroutine reacts promptly even under the race detector.
				if localTried&(cancelCheckInterval-1) == 0 && localTried > 0 {
					if ctx.Err() != nil {
						tried.Add(progressAccum)
						return
					}
					if found.Load() != 0 {
						tried.Add(progressAccum)
						return
					}
					// Report progress at coarser granularity.
					if progressAccum >= progressInterval {
						tried.Add(progressAccum)
						progressAccum = 0
						reportProgress()
					}
				}
				localTried++
				progressAccum++

				if Encrypt(cfg.KnownPlaintext, k) == cfg.KnownCiphertext {
					once.Do(func() {
						foundKey.Store(k)
						found.Store(1)
					})
					tried.Add(progressAccum)
					return
				}
			}
			// flush remaining progress
			tried.Add(progressAccum)
		}(lo, hi)
	}

	wg.Wait()

	if ctx.Err() != nil {
		return 0, false, ctx.Err()
	}
	if found.Load() != 0 {
		return foundKey.Load(), true, nil
	}
	return 0, false, nil
}
