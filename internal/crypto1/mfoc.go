// SPDX-License-Identifier: AGPL-3.0-or-later

// mfoc.go — pure-Go offline nested-authentication key recovery.
//
// This implements the offline portion of the classical mfoc (MIFARE Classic
// nested attack) from Garcia et al. ESORICS 2008.  The live-NFC phase (driving
// a real reader) is handled by the Flipper / Proxmark3 integration layer; this
// package handles the cryptographic core that can run without any hardware.
//
// # Background
//
// MIFARE Classic's "nested authentication" feature lets a reader authenticate
// to a second sector without going through a full anticollision cycle.  In a
// nested auth the card sends the new sector's nT encrypted under the cipher
// state left over from the previous (known-sector) authentication, rather than
// as a plain random value.  This encrypted nT leaks information: an attacker
// who knows the cipher state at the end of the previous auth can decrypt the
// nT for the new sector, which yields a valid (uid, nt, nr, ar) tuple that
// can be fed directly to the mfkey32 rollback in mfkey32.go.
//
// # Data capture model
//
// Each NestedAttempt captures one complete nested authentication sequence.
// The attacker re-authenticates to the known sector before each nested
// attempt, so the cipher is reset to a fresh known-state for every attempt.
// Concretely, each attempt has:
//
//   - KnownNT, KnownNR: nonces of the known-sector re-authentication for
//     this attempt (the tag issues a fresh nT each time, and the reader
//     chooses a fresh nR — both are captured by the sniffer).
//   - NTEnc: the encrypted nT the card sent for the target sector in the
//     nested authentication (on-wire value).
//   - NR, AR: the reader nonce sent to the target sector, and the card's
//     encrypted aR response, both captured by the sniffer.
//
// RecoverNested decrypts each NTEnc to obtain a plain (nt, nr, ar) tuple,
// then feeds the first two tuples into the mfkey32 rollback to recover the
// target sector key.
package crypto1

import (
	"errors"
)

// NestedCapture is the full set of sniffed data needed for one offline nested
// attack.  It groups the known-sector credentials and the nested-auth
// attempts against the target sector.
type NestedCapture struct {
	// UID is the card UID (4 bytes, big-endian word).
	UID uint32

	// KnownKey is the 48-bit sector key that is already known to the attacker
	// (low 48 bits of uint64).  The known sector must have been authenticated
	// at least once before each nested attempt.
	KnownKey uint64

	// Attempts contains the sniffed data from each nested authentication
	// attempt.  At least 2 attempts are required for the mfkey32 intersection.
	// There is no benefit in passing more than 2; additional attempts are
	// ignored.
	Attempts []NestedAttempt
}

// NestedAttempt captures one nested authentication round:
//   - The known-sector authentication nonces for this particular re-auth
//     (KnownNT, KnownNR) — they change every attempt because the tag's PRNG
//     advances and the reader picks a fresh nR.
//   - The nested target-sector nT as it appeared on the wire (NTEnc) —
//     encrypted under the known-sector cipher state.
//   - The reader nonce sent to the target sector (NR) and the card's aR
//     response (AR) — both captured from the wire.  These are the same
//     (uid, nt, nr, ar) tuple shape that mfkey32_recover expects once NTEnc
//     has been decrypted.
type NestedAttempt struct {
	// KnownNT is the plain tag nonce from the known-sector re-authentication
	// that precedes this nested attempt.
	KnownNT uint32

	// KnownNR is the plain reader nonce the reader sent to the known sector.
	KnownNR uint32

	// NTEnc is the encrypted (nested) tag nonce for the target sector, as
	// observed on the wire.
	NTEnc uint32

	// NR is the plain reader nonce sent to the target sector.
	NR uint32

	// AR is the tag's encrypted aR response to the target-sector auth
	// challenge, as observed on the wire.
	AR uint32
}

// nestedDecrypted is an intermediate result: one decrypted (NT, NR, AR) tuple
// ready to be fed into the mfkey32 rollback.
type nestedDecrypted struct {
	NT, NR, AR uint32
}

// RecoverNested recovers the 48-bit target-sector key from a NestedCapture.
//
// Algorithm:
//
//  1. For each NestedAttempt, reconstruct the cipher state at the point where
//     the card encrypts the nested nT:
//     a. Init cipher with KnownKey.
//     b. CryptFeedback(uid ^ KnownNT) — advance through the known-sector nT
//     phase (32 clocks, nT mixes into LFSR).
//     c. EncCrypt(KnownNR, 0) — advance through the known-sector nR phase
//     (32 clocks, plain nR feeds LFSR).
//     d. Crypt(0) — advance through the known-sector aR phase (32 clocks,
//     no external feedback); cipher is now at "end of known auth".
//     e. Crypt(0) — produce the 32-bit keystream used to encrypt the nested
//     nT; XOR with NTEnc → plain NT for the target sector.
//
//  2. Collect the (NT, NR, AR) tuples from the first two attempts.
//
//  3. Call RecoverWithRange on those two tuples, restricting the hi32 search
//     to 0..loHi (determined by the search range argument, defaulting to 1 for
//     a 16-bit search that finishes in <100 ms for typical test vectors).
//
// The function returns the recovered 48-bit key (low 48 bits of uint64) or an
// error if no matching key was found in the default 16-bit search range.
//
// For production use with unknown keys, call RecoverNestedWithRange with a
// larger range (up to 1<<32 for full 48-bit coverage).
func RecoverNested(c NestedCapture) (uint64, error) {
	// Default: search keys where bits 47..16 == 0 (16-bit key space, ~70 ms).
	return RecoverNestedWithRange(c, 0, 1)
}

// RecoverNestedWithRange is RecoverNested with an explicit high-32-bit search
// range [loHi, hiHi).  See RecoverWithRange for range semantics.
func RecoverNestedWithRange(c NestedCapture, loHi, hiHi uint64) (uint64, error) {
	if len(c.Attempts) < 2 {
		return 0, errors.New("mfoc: at least 2 nested attempts are required for key recovery")
	}

	tuples, err := decryptNestedAttempts(c.UID, c.KnownKey, c.Attempts)
	if err != nil {
		return 0, err
	}

	// Tuples[0] and tuples[1] are now (NT, NR, AR) pairs for the target sector.
	t0, t1 := tuples[0], tuples[1]
	return RecoverWithRange(
		c.UID,
		t0.NT, t0.NR, t0.AR,
		t1.NT, t1.NR, t1.AR,
		loHi, hiHi,
	)
}

// decryptNestedAttempts decrypts each NestedAttempt's encrypted nT into a
// plain (NT, NR, AR) tuple using the known-key cipher state.  Returns a slice
// of nestedDecrypted in the same order as the input attempts.
//
// Each attempt is independent: the cipher is re-seeded from KnownKey for
// every attempt, walked through that attempt's known-sector nonces, and then
// the keystream at the nested-nT position is used to decrypt NTEnc.
func decryptNestedAttempts(uid uint32, knownKey uint64, attempts []NestedAttempt) ([]nestedDecrypted, error) {
	out := make([]nestedDecrypted, len(attempts))
	for i, a := range attempts {
		c := New()
		c.Init(knownKey)

		// Step through the known-sector authentication using this attempt's
		// nonces.  After these three calls the cipher is at "end of known
		// sector authentication" — exactly where the card would begin
		// encrypting the nested nT.
		c.CryptFeedback(uid ^ a.KnownNT)
		c.EncCrypt(a.KnownNR, 0)
		c.Crypt(0) // consume aR-phase keystream; no external feedback

		// The next 32 keystream bits encrypt the nested nT.
		ks := c.Crypt(0)
		nt := a.NTEnc ^ ks

		out[i] = nestedDecrypted{NT: nt, NR: a.NR, AR: a.AR}
	}
	return out, nil
}
