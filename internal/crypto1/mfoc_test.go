// SPDX-License-Identifier: AGPL-3.0-or-later
package crypto1

import (
	"testing"
)

// synthesizeNestedCapture builds a NestedCapture for a given target key by
// simulating both sides of the authentication exchange.
//
// For each attempt:
//  1. Simulate a known-sector authentication with knownKey, uid, and the
//     attempt's KnownNT/KnownNR.  The cipher is walked to "end of known auth".
//  2. Produce the encrypted nested nT by XORing the actual target NT with the
//     next 32 keystream bits.
//  3. Produce the on-wire AR using the target sector's key via AuthEncrypt.
func synthesizeNestedCapture(targetKey, knownKey uint64, uid uint32, attempts []NestedAttempt) NestedCapture {
	for i, a := range attempts {
		// Walk the known-sector cipher to the "end of known auth" point.
		c := New()
		c.Init(knownKey)
		c.CryptFeedback(uid ^ a.KnownNT)
		c.EncCrypt(a.KnownNR, 0)
		c.Crypt(0) // consume aR-phase keystream

		// The next 32 keystream bits would encrypt the nested nT.
		// a.NTEnc ^ Crypt(0) = targetNT  →  a.NTEnc = targetNT ^ Crypt(0).
		// Here a.NR is the plain reader nonce the attacker chose; we need the
		// on-wire AR from the target sector.  Compute AR using the target key.
		ks := c.Crypt(0)
		// NTEnc = targetNT ^ ks  where targetNT = Prng(someNT, n); for test
		// purposes use a.NR itself as the "plain target NT" for simplicity, but
		// we need something that maps back correctly.  Use a.NTEnc as the field
		// where we store the target NT, compute NTEnc in the returned struct.
		//
		// We require a.NTEnc to hold the PLAIN target NT as input here;
		// synthesizeNestedCapture replaces it with the encrypted value.
		plainNT := a.NTEnc // caller supplies the plain target NT in NTEnc temporarily

		// Encrypt the plain NT.
		attempts[i].NTEnc = plainNT ^ ks

		// Produce the on-wire AR for the target sector using AuthEncrypt.
		cap := AuthCapture{NT: plainNT, NR: a.NR}
		_, ar := AuthEncrypt(targetKey, uid, cap)
		attempts[i].AR = ar
	}

	return NestedCapture{
		UID:      uid,
		KnownKey: knownKey,
		Attempts: attempts,
	}
}

// mfocVector groups the inputs and expected output for one closed-loop test.
// Keys are 16-bit so RecoverNestedWithRange(…, 0, 1) finds them in ~70 ms.
type mfocVector struct {
	name      string
	targetKey uint64 // 16-bit key to recover
	knownKey  uint64 // known sector key (can be any key for test purposes)
	uid       uint32
	// Each attempt specifies: KnownNT, KnownNR, and plainTargetNT (stored in
	// the NTEnc field before synthesis replaces it with the encrypted value).
	// NR is the reader nonce chosen for the target sector auth.
	attempts []NestedAttempt
}

var mfocVectors = []mfocVector{
	{
		name:      "targetKey=0x1234",
		targetKey: 0x1234,
		knownKey:  0xA0A1A2A3A4A5,
		uid:       0xCAFEBABE,
		attempts: []NestedAttempt{
			{KnownNT: 0x01020304, KnownNR: 0xDEADBEEF, NTEnc: 0xABCDABCD, NR: 0x11223344},
			{KnownNT: 0xE93E12E4, KnownNR: 0x55667788, NTEnc: 0xDEAD1234, NR: 0x99AABBCC},
		},
	},
	{
		name:      "targetKey=0x505A",
		targetKey: 0x505A,
		knownKey:  0xFFFFFFFFFFFF,
		uid:       0x12345678,
		attempts: []NestedAttempt{
			{KnownNT: 0xABCDEF01, KnownNR: 0x98765432, NTEnc: 0x11111111, NR: 0xFEDCBA98},
			{KnownNT: 0x11111111, KnownNR: 0xFEDCBA98, NTEnc: 0x55443322, NR: 0x12348765},
		},
	},
	{
		name:      "targetKey=0x0000 (corner case)",
		targetKey: 0x0000,
		knownKey:  0xA0B0C0D0E0F0,
		uid:       0xAABBCCDD,
		attempts: []NestedAttempt{
			{KnownNT: 0xDEADBEEF, KnownNR: 0x00000001, NTEnc: 0xCAFEBABE, NR: 0x00000002},
			{KnownNT: 0xCAFEBABE, KnownNR: 0x00000002, NTEnc: 0xBEEFCAFE, NR: 0x00000003},
		},
	},
}

// TestMfocClosedLoop verifies that RecoverNestedWithRange recovers the target
// key for all mfocVectors.  Synthesis via synthesizeNestedCapture ensures the
// test does not depend on any external data source.
func TestMfocClosedLoop(t *testing.T) {
	if testing.Short() {
		t.Skip("TestMfocClosedLoop (~70 ms per vector): skipped in -short mode")
	}

	for _, v := range mfocVectors {
		v := v
		t.Run(v.name, func(t *testing.T) {
			// synthesizeNestedCapture modifies the attempts slice in-place.
			// Make a deep copy so the vector is not mutated.
			attemptsCP := make([]NestedAttempt, len(v.attempts))
			copy(attemptsCP, v.attempts)

			cap := synthesizeNestedCapture(v.targetKey, v.knownKey, v.uid, attemptsCP)

			got, err := RecoverNestedWithRange(cap, 0, 1)
			if err != nil {
				t.Fatalf("RecoverNested failed: %v", err)
			}
			if got != v.targetKey {
				t.Errorf("RecoverNested = 0x%012X; want 0x%012X", got, v.targetKey)
			}
		})
	}
}

// TestMfocDecryptRoundTrip verifies that decryptNestedAttempts correctly
// undoes the synthetic encryption: the decrypted NT should match the plain NT
// that was put in before synthesis.
func TestMfocDecryptRoundTrip(t *testing.T) {
	const (
		knownKey  = uint64(0xA0A1A2A3A4A5)
		targetKey = uint64(0x1234)
		uid       = uint32(0xCAFEBABE)
	)

	plainNT0 := uint32(0xABCDABCD)
	plainNT1 := uint32(0xDEAD1234)

	attempts := []NestedAttempt{
		{KnownNT: 0x01020304, KnownNR: 0xDEADBEEF, NTEnc: plainNT0, NR: 0x11223344},
		{KnownNT: 0xE93E12E4, KnownNR: 0x55667788, NTEnc: plainNT1, NR: 0x99AABBCC},
	}

	cap := synthesizeNestedCapture(targetKey, knownKey, uid, attempts)

	tuples, err := decryptNestedAttempts(uid, knownKey, cap.Attempts)
	if err != nil {
		t.Fatalf("decryptNestedAttempts: %v", err)
	}

	if tuples[0].NT != plainNT0 {
		t.Errorf("attempt 0 decrypted NT = 0x%08X; want 0x%08X", tuples[0].NT, plainNT0)
	}
	if tuples[1].NT != plainNT1 {
		t.Errorf("attempt 1 decrypted NT = 0x%08X; want 0x%08X", tuples[1].NT, plainNT1)
	}
}

// TestMfocTooFewAttempts verifies that RecoverNested returns a descriptive
// error when fewer than 2 attempts are provided.
func TestMfocTooFewAttempts(t *testing.T) {
	cap := NestedCapture{
		UID:      0xCAFEBABE,
		KnownKey: 0xA0A1A2A3A4A5,
		Attempts: []NestedAttempt{
			{KnownNT: 0x01020304, KnownNR: 0xDEADBEEF, NTEnc: 0x12345678, NR: 0x11223344},
		},
	}
	_, err := RecoverNested(cap)
	if err == nil {
		t.Fatal("expected error for < 2 attempts")
	}
}
