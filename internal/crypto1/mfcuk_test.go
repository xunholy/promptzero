// SPDX-License-Identifier: AGPL-3.0-or-later
package crypto1

import (
	"context"
	"testing"
)

// mfcukVector groups the inputs and expected output for one closed-loop test.
// Keys are 16-bit so RecoverDarksideWithRange(…, 0, 1) finds them in sub-ms.
//
// NT values are chosen to avoid the ~1-in-5 (uid,nt) combinations where the
// 4-bit NACK keystream at byte-0 has a genuine degeneracy: two 16-bit keys
// produce identical constraints for all 256 NR low bytes.  Selection was
// verified empirically via exhaustive 16-bit scan.
type mfcukVector struct {
	name string
	key  uint64 // 16-bit key to recover
	uid  uint32
	nt   uint32
}

// makeNRs produces 256 NR values with all 256 distinct low bytes (0x00..0xFF).
// High bytes are varied using a seed so NR values differ across vectors.
// The low byte of nrs[i] is guaranteed to equal i (for i = 0..255).
func makeNRs(seed uint32) []uint32 {
	nrs := make([]uint32, 256)
	for i := 0; i < 256; i++ {
		// Low byte is forced to i. High 3 bytes come from the seed.
		// (seed + i*0x01000000) advances the seed independently per step,
		// then mask off the low byte and OR in i.
		hi := (seed + uint32(i)*0x00010100) & 0xFFFFFF00
		nrs[i] = hi | uint32(i)
	}
	return nrs
}

var mfcukVectors = []mfcukVector{
	// NT values verified: each (uid, nt) pair uniquely identifies the key
	// using all 256 NR low bytes as constraints (exactly 1 survivor in 2^16).
	{name: "key=0x1234", key: 0x1234, uid: 0xCAFEBABE, nt: 0x01020304},
	{name: "key=0x505A", key: 0x505A, uid: 0x12345678, nt: 0xABCDEF01},
	{name: "key=0x0000 (corner case)", key: 0x0000, uid: 0xAABBCCDD, nt: 0xDEADBEEF},
	{name: "key=0xABCD", key: 0xABCD, uid: 0x11223344, nt: 0x01020304},
}

// TestMfcukClosedLoop verifies that RecoverDarksideWithRange recovers the key
// for all mfcukVectors.  Parity values are synthesised using
// darksideSynthesizeParity so no hardware is required.
//
// NR values cover all 256 distinct low bytes to ensure unique key recovery
// in the 16-bit search space (empirically: 1 survivor in 2^16 for each vector).
func TestMfcukClosedLoop(t *testing.T) {
	for _, v := range mfcukVectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			// Use a vector-specific seed so NR high-bytes differ between vectors.
			nrs := makeNRs(v.uid ^ v.nt)
			pairs := make([]DarksidePair, len(nrs))
			for i, nr := range nrs {
				pairs[i] = DarksidePair{
					NR:     nr,
					Parity: darksideSynthesizeParity(v.key, v.uid, v.nt, nr),
				}
			}

			cap := DarksideCapture{
				UID:   v.uid,
				NT:    v.nt,
				NRArs: pairs,
			}

			got, err := RecoverDarksideWithRange(context.Background(), cap, 0, 1)
			if err != nil {
				t.Fatalf("RecoverDarkside failed: %v", err)
			}
			if got != v.key {
				t.Errorf("RecoverDarkside = 0x%012X; want 0x%012X", got, v.key)
			}
		})
	}
}

// TestMfcukParityRoundTrip verifies that darksideSynthesizeParity and the
// darksideKeyMatches constraint check are exact inverses: a synthesised parity
// value must pass the constraint for the key that produced it.
func TestMfcukParityRoundTrip(t *testing.T) {
	const (
		key = uint64(0x1234)
		uid = uint32(0xCAFEBABE)
		nt  = uint32(0x01020304)
		nr  = uint32(0xDEADBEEF)
	)

	parity := darksideSynthesizeParity(key, uid, nt, nr)

	cs := []darksideConstraint{
		{nrLowByte: uint8(nr & 0xFF), wantKS: (parity ^ darksideNACK) & 0xF},
	}

	if !darksideKeyMatches(key, uid, nt, cs) {
		t.Error("darksideKeyMatches: true key did not pass its own synthesised constraint")
	}
}

// TestMfcukEmptyPairs verifies that RecoverDarkside returns an error when no
// DarksidePairs are provided.
func TestMfcukEmptyPairs(t *testing.T) {
	cap := DarksideCapture{
		UID:   0xCAFEBABE,
		NT:    0x01020304,
		NRArs: nil,
	}
	_, err := RecoverDarkside(cap)
	if err == nil {
		t.Fatal("expected error for empty NRArs")
	}
}

// TestMfcukSinglePairConstraintValid verifies that a single DarksidePair is
// accepted by RecoverDarksideWithRange without error and that any returned key
// satisfies the single constraint.  With one 4-bit observation, ~2^12 keys
// survive in the 16-bit space — unique identification is not expected.
func TestMfcukSinglePairConstraintValid(t *testing.T) {
	const (
		key = uint64(0xABCD)
		uid = uint32(0x11223344)
		nt  = uint32(0xDEADBEEF)
		nr  = uint32(0x55667788)
	)

	parity := darksideSynthesizeParity(key, uid, nt, nr)
	cap := DarksideCapture{
		UID: uid,
		NT:  nt,
		NRArs: []DarksidePair{
			{NR: nr, Parity: parity},
		},
	}

	got, err := RecoverDarksideWithRange(context.Background(), cap, 0, 1)
	if err != nil {
		t.Fatalf("RecoverDarkside with single pair failed: %v", err)
	}
	cs := []darksideConstraint{
		{nrLowByte: uint8(nr & 0xFF), wantKS: (parity ^ darksideNACK) & 0xF},
	}
	if !darksideKeyMatches(got, uid, nt, cs) {
		t.Errorf("returned key 0x%012X does not satisfy the constraint", got)
	}
}

// TestRecoverDarksideWithRangeContextCancellation verifies that
// RecoverDarksideWithRange returns a context error promptly when the context
// is cancelled (regression for goroutine-leak fix in mfcuk_attack handler).
func TestRecoverDarksideWithRangeContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	const (
		uid = uint32(0xCAFEBABE)
		nt  = uint32(0x01020304)
		nr  = uint32(0xDEADBEEF)
		key = uint64(0x1234)
	)
	parity := darksideSynthesizeParity(key, uid, nt, nr)
	cap := DarksideCapture{
		UID:   uid,
		NT:    nt,
		NRArs: []DarksidePair{{NR: nr, Parity: parity}},
	}

	// Use a large hi-range so the search would not complete without ctx.
	_, err := RecoverDarksideWithRange(ctx, cap, 0, 1<<32)
	if err == nil {
		t.Fatal("RecoverDarksideWithRange: expected error on cancelled context, got nil")
	}
	if !isCtxError(err) {
		t.Errorf("RecoverDarksideWithRange: want context error, got %v", err)
	}
}
