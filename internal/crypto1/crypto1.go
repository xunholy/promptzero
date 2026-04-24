// Package crypto1 is the pure-Go implementation of the Crypto1 stream
// cipher used by MIFARE Classic and some HID iCLASS legacy systems.
//
// Status: INTERFACE ONLY (v0.5 wave-1 architect skeleton).
// The algorithm body lands in v0.5 wave-2, implemented by the engineer
// claiming task #7 (Mifare crackers — pure-Go port). Until then every
// method is a stub returning zero values; tests in crypto1_test.go
// skip with `t.Skip("impl in wave 2")`.
//
// # Algorithm overview
//
// Crypto1 is a 48-bit LFSR-based stream cipher. State is a 48-bit
// register; a non-linear output filter f(x) produces one keystream bit
// per clock. The filter is built from five boolean functions f_a, f_b,
// f_c at specific tap positions:
//
//	odd  = bits 47, 43, 41, 39, 37, 35, 33, 31, 29, 27, 25, 23
//	even = bits 46, 44, 42, 40, 38, 36, 34, 32, 30, 28, 26, 24
//
// The output filter combines selected odd+even taps through f_a / f_b
// to yield a single keystream bit, XORed with the plaintext. See the
// public literature:
//
//   - Garcia, de Koning Gans, Muijrers, van Rossum, Verdult, Schreur,
//     Jacobs. "Dismantling MIFARE Classic." ESORICS 2008.
//   - Courtois, Nohl, O'Neil. "Algebraic Attacks on the CRYPTO1
//     Stream Cipher in MiFare Classic and Oyster Cards." IACR 2008.
//
// The reference C implementations live in nfc-tools/mfoc,
// nfc-tools/mfcuk, and equipter/mfkey32v2 — all three use the same LFSR
// tap set. The pure-Go port should be algorithm-only (clean-room
// reimplementation from the papers; do NOT copy the C source).
//
// # Thread safety
//
// A Cipher is not safe for concurrent use. Create one per goroutine,
// or serialise access with a mutex. Reuse across packets is expected:
// Init rewires the state from the new key, Crypt advances the LFSR.
//
// # API contract
//
// The three methods (Init, Crypt, EncCrypt) cover every use case the
// v0.5 crackers need:
//
//   - Init(key uint64)           — load the 48-bit sector key.
//   - Crypt(input uint32) uint32 — clock the LFSR once per input bit,
//     XOR the keystream with input, return the result. Used to decrypt
//     reader/tag frames during a captured session.
//   - EncCrypt(input, nr uint32) uint32 — as Crypt, but additionally
//     feeds (input XOR nr) back into the LFSR — the "nR mode" that the
//     MIFARE authentication exchange uses after the initial challenge.
//
// Bit ordering follows the reference impls: input is LSB-first; the
// LFSR state has bit 0 as the freshest shift-in position.
//
// # Test-vector sources
//
// The v0.5 wave-2 engineer's test suite draws from two public corpora:
//
//  1. The mfoc-hardnested test harness at
//     `nfc-tools/mfoc-hardnested/src/cmdhfmfhard.c` includes a
//     self-check fixture: key=0xFFFFFFFFFFFF, UID=0xCAFEBABE,
//     nT=0x01020304, expected keystream bytes are pinned there.
//
//  2. The Proxmark3 iceman fork's `armsrc/mifarecmd.c` ships a
//     known-answer test for the Courtois-rollback primitive used by
//     mfkey32 / mfkey32v2.
//
// Both fixtures are small (<1 KB each) and can be embedded into
// crypto1_test.go verbatim. See docs/refactor/v0.5-runbook.md §D for
// the full test-vector contract.
//
// # License posture
//
// The Crypto1 algorithm is in the public research literature (ESORICS
// 2008, IACR 2008). The reference C impls are LGPL (mfoc/mfcuk) or
// GPLv2 (proxmark3). A clean-room Go reimplementation from the papers
// gives PromptZero the flexibility to keep its AGPL-3.0-or-later
// licence without inheriting LGPL/GPL obligations — classified
// `clean-reimpl` in the runbook §E license table.
package crypto1

// Cipher is a Crypto1 LFSR state. Zero value is invalid — call Init
// before any Crypt / EncCrypt. Reinit is allowed and expected between
// MIFARE authentication exchanges.
type Cipher struct {
	// state is the 48-bit LFSR. Only the low 48 bits are meaningful;
	// the high 16 bits are always zero. The unexported field prevents
	// callers from poking it directly — Init is the only sanctioned
	// way to seed the cipher.
	//
	// Linted-unused until wave 2: the skeleton methods don't touch
	// the field yet. The `var _ = (&Cipher{}).state` line below
	// keeps the linter quiet without polluting every method with a
	// `_ = c.state` dance.
	state uint64
}

// Keep the `state` field referenced until wave 2 wires it up. Using
// an assignment-into-blank on a zero-value Cipher means zero runtime
// cost and zero allocations.
var _ = Cipher{}.state

// New returns a zero-valued Cipher. Equivalent to `var c Cipher`; the
// constructor exists so callers can write `c := crypto1.New()` in the
// style of other internal packages, and so future additions (e.g. an
// allocation-free object pool) have a single call site to migrate.
func New() *Cipher {
	return &Cipher{}
}

// Init seeds the LFSR from the 48-bit sector key. The high 16 bits of
// key are ignored. Must be called before any Crypt / EncCrypt.
//
// Wave 2 impl: spread key across the 48 LFSR positions per the
// MIFARE spec (bit 0 of key → LFSR bit 0, bit 47 of key → LFSR bit
// 47). Reference: mfoc/src/crapto1.c:crypto1_init.
func (c *Cipher) Init(key uint64) {
	_ = key
	// TODO(v0.5 wave 2): wire the LFSR state per the MIFARE spec.
}

// Crypt clocks the LFSR `len(input)` bits and XORs the keystream with
// the plaintext. Returns the ciphertext (or plaintext when decrypting
// — Crypto1 is symmetric).
//
// Bit ordering: input LSB-first, keystream LSB-first. Output has the
// same bit width as input.
//
// Wave 2 impl: per bit, compute filter(state), XOR with the input bit,
// shift the state left with the filter output fed back per the MIFARE
// recurrence (state[47] ← state[46] ⊕ state[44] ⊕ state[42] ⊕
// state[39] ⊕ state[37] ⊕ state[33] ⊕ input_feedback_bit).
func (c *Cipher) Crypt(input uint32) uint32 {
	_ = input
	// TODO(v0.5 wave 2): advance the LFSR, XOR the keystream with input.
	return 0
}

// EncCrypt is Crypt with an extra feedback term — the reader nonce
// (nr) is XORed with each bit of input and mixed into the LFSR's
// feedback path. Used during the MIFARE authentication exchange for
// the `a_r` / `a_t` responses, NOT for the subsequent command stream.
//
// Wave 2 impl: same as Crypt, but the feedback bit is (state_feedback
// ⊕ input_bit ⊕ nr_bit) rather than (state_feedback ⊕ input_bit).
func (c *Cipher) EncCrypt(input, nr uint32) uint32 {
	_ = input
	_ = nr
	// TODO(v0.5 wave 2): advance the LFSR with nr feedback, XOR keystream.
	return 0
}

// Prng is the PRNG side-channel used by mfkey32v2 / hardnested. The
// MIFARE Classic tag advances a weak 16-bit LFSR between
// authentications; recovering its seed from a captured nT is part of
// the darkside / hardnested recovery chain.
//
// Exposed as a standalone function (not a Cipher method) because it
// does not touch the Crypto1 LFSR state — the two state machines are
// independent despite being used together.
//
// Wave 2 impl: LFSR polynomial x^16 + x^14 + x^13 + x^11 + 1 per the
// MIFARE spec. Seed is 32 bits but the LFSR is 16-bit; the two halves
// are advanced in lockstep and concatenated on output. Reference:
// mfcuk/src/crapto1.c:prng_successor.
//
//nolint:unused // Wire-up in wave 2.
func Prng(from uint32, n int) uint32 {
	_ = from
	_ = n
	// TODO(v0.5 wave 2): run the 16-bit Mersenne-like PRNG forward n
	// cycles and return the resulting 32-bit state.
	return 0
}
