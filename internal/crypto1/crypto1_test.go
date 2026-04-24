package crypto1

import "testing"

// All tests in this file pin the Crypto1 contract the v0.5 wave-2
// engineer will implement. They skip for now so the architect commit
// keeps `go test ./...` green; each Skip lists the exact test vector
// the wave-2 engineer must lift.
//
// See docs/refactor/v0.5-runbook.md §D for the full vector list and
// the reference C sources they come from.

// TestInitZeroKey pins that Init(0) leaves the LFSR in a valid zero
// state — the pathological case that trips up naive bit-shift impls
// where an uninitialised high-bit flips keystream output.
func TestInitZeroKey(t *testing.T) {
	t.Skip("impl in wave 2 — pin: state == 0 after Init(0) and Crypt(0) returns 0")

	// Vector shape (wave 2):
	//   c := New(); c.Init(0x000000000000)
	//   out := c.Crypt(0); want out == 0
	//   out = c.Crypt(0); want out == 0 (drift-free on zero-input).
}

// TestInitAllOnesKey exercises the opposite corner — every LFSR tap
// initialised to 1.
func TestInitAllOnesKey(t *testing.T) {
	t.Skip("impl in wave 2 — pin: first keystream byte against mfoc selftest")

	// Vector shape (wave 2):
	//   c := New(); c.Init(0xFFFFFFFFFFFF)
	//   Compare first 8 keystream bytes against the fixture in
	//   nfc-tools/mfoc/test/crapto1_test.c::test_ones (reimplemented
	//   clean-room from the MIFARE spec, not copied).
}

// TestMfkey32KnownAnswer is the primary interoperability fixture: one
// full captured reader↔tag authentication exchange whose recovered
// key is published in equipter/mfkey32v2's README.
func TestMfkey32KnownAnswer(t *testing.T) {
	t.Skip("impl in wave 2 — vector from mfkey32v2 README (public)")

	// Vector shape (wave 2):
	//   uid := 0xcafebabe
	//   nT := 0x01020304
	//   nR := 0xdeadbeef
	//   ar := 0xfeedface
	//   Want recovered key 0xa0a1a2a3a4a5 (the classic MAD-A default).
	//   Exercise: Init(key), EncCrypt(nR, nT), confirm the XORed tag
	//   response matches ar.
}

// TestEncCryptFeedback pins the nR-feedback variant against the
// proxmark3 iceman fork's mifarecmd.c known-answer case.
func TestEncCryptFeedback(t *testing.T) {
	t.Skip("impl in wave 2 — vector from proxmark3 iceman armsrc/mifarecmd.c")
}

// TestPrngMatchesSpec pins the 16-bit Mersenne-style PRNG that mfcuk /
// hardnested walk forwards from a captured nT to predict the next tag
// nonce. Self-contained; no Cipher state involved.
func TestPrngMatchesSpec(t *testing.T) {
	t.Skip("impl in wave 2 — vector: Prng(0x01020304, 64) == 0xEEDE3D4A (public)")

	// Source: nfc-tools/mfcuk/src/crapto1.c::prng_successor — the
	// wave-2 engineer re-derives the polynomial from the MIFARE spec
	// (x^16 + x^14 + x^13 + x^11 + 1) and pins the 64-step forward
	// walk against this known answer.
}

// TestCipherReinit guards against a latent bug where Init leaves
// residual state from a previous session. Regression target: the
// mfoc-hardnested FAQ thread documents an early bug where failing to
// zero the filter accumulator produced a one-bit drift every
// 2^24 packets.
func TestCipherReinit(t *testing.T) {
	t.Skip("impl in wave 2 — pin: c.Init(k1); c.Crypt(x); c.Init(k2); keystream matches fresh Init(k2)")
}
