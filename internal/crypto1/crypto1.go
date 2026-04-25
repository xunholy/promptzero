// Package crypto1 is the pure-Go implementation of the Crypto1 stream
// cipher used by MIFARE Classic and some HID iCLASS legacy systems.
//
// # Algorithm overview
//
// Crypto1 is a 48-bit LFSR-based stream cipher. State is a 48-bit
// register; a non-linear output filter f(x) produces one keystream bit
// per clock. The filter is built from boolean functions f_a, f_b, f_c
// at specific tap positions (see filterOutput below).
//
// References (clean-room reimplementation from the public papers; do
// NOT copy mfoc/mfcuk/proxmark3 C source):
//
//   - Garcia, de Koning Gans, Muijrers, van Rossum, Verdult, Schreur,
//     Jacobs. "Dismantling MIFARE Classic." ESORICS 2008.
//   - Courtois, Nohl, O'Neil. "Algebraic Attacks on the CRYPTO1
//     Stream Cipher in MiFare Classic and Oyster Cards." IACR 2008.
//
// # Thread safety
//
// A Cipher is not safe for concurrent use. Create one per goroutine,
// or serialise access externally.
//
// # API surface
//
//   - Init(key uint64)             — load the 48-bit sector key into
//                                    LFSR positions 0..47.
//   - Crypt(input uint32) uint32   — clock LFSR 32 times, XOR
//                                    keystream with input. NO external
//                                    feedback. Symmetric.
//   - EncCrypt(input, nr uint32)   — like Crypt, but mixes input bits
//                                    into LFSR feedback (used during
//                                    the reader-nonce phase of MIFARE
//                                    auth).
//   - CryptFeedback(in uint32)     — feeds external bits into LFSR
//                                    feedback while running keystream
//                                    (used during the tag-nonce nT
//                                    phase of MIFARE auth).
//   - Prng(from uint32, n int)     — advance the tag PRNG (16-bit
//                                    LFSR pair, x^16 + x^14 + x^13 +
//                                    x^11 + 1) n cycles.
//
// # Bit ordering
//
// All inputs and outputs are LSB-first. The 48-bit LFSR has bit 0 as
// the freshest shift-in position; new bits enter at bit 47 each clock.
// Inputs to Crypt/EncCrypt/CryptFeedback are processed bit-by-bit,
// LSB first, for `len(input)*8` clocks; with input as uint32 we run
// 32 clocks.
package crypto1

// LFSR feedback taps (Garcia et al. §3.3, expanded form). Bits whose
// XOR forms the new high bit each clock. Verified to match mfoc's
// crapto1.c LF_POLY_ODD/LF_POLY_EVEN combined polynomial coefficients.
var lfsrTaps = [...]int{0, 5, 9, 10, 12, 14, 15, 17, 19, 24, 25, 27, 29, 35, 39, 41, 42, 43}

// Cipher is a 48-bit Crypto1 LFSR. Zero value is invalid; call Init
// before any Crypt / EncCrypt / CryptFeedback. Reinit is allowed and
// expected between MIFARE authentication exchanges.
type Cipher struct {
	// state is the 48-bit LFSR. Only the low 48 bits are meaningful;
	// the high 16 bits remain zero. Encoded LSB-first: bit 0 is the
	// position that shifts out next, bit 47 is the position the new
	// feedback bit enters into.
	state uint64
}

// New returns a fresh Cipher. Equivalent to `var c Cipher`; provided
// for symmetry with the wider PromptZero `New()` constructor convention.
func New() *Cipher { return &Cipher{} }

// Init seeds the LFSR from the low 48 bits of key. The high 16 bits of
// key are ignored.
//
// Bit-spread: key bit i lands in LFSR position i for i in 0..47, so
// `Init(key); ks := c.Crypt(0)` produces a deterministic keystream
// derived purely from key.
func (c *Cipher) Init(key uint64) {
	c.state = key & 0xFFFFFFFFFFFF
}

// Crypt clocks the LFSR 32 times producing 32 keystream bits, XORs
// them with the input bits (LSB-first), and returns the ciphertext.
// No external feedback — the LFSR purely advances under its own
// recurrence. Symmetric: applying twice with the same key recovers
// the plaintext.
func (c *Cipher) Crypt(input uint32) uint32 {
	var out uint32
	for i := uint(0); i < 32; i++ {
		ks := filterOutput(c.state)
		fb := feedbackBit(c.state)
		bit := uint32((input >> i) & 1)
		out |= uint32(ks) << i
		c.state = (c.state >> 1) | (fb << 47)
		_ = bit // Crypt doesn't feed input bit back into LFSR
	}
	return out ^ input
}

// EncCrypt is Crypt plus reader-nonce feedback: each input bit XOR'd
// with the corresponding nr bit is fed into the LFSR's high position.
// Used during the MIFARE Classic auth nR phase, where the plain reader
// nonce mixes into the cipher state.
//
// Note: the canonical convention in Garcia et al. has the input plain
// bit (not nr) feed back into the LFSR. We follow that — `nr` is
// retained as the second argument so callers wishing to model the
// "nR plain feed" can pass the same value as input. The single-arg
// case (callers passing nr=0) reduces to vanilla feed-input-into-LFSR.
func (c *Cipher) EncCrypt(input, nr uint32) uint32 {
	var out uint32
	for i := uint(0); i < 32; i++ {
		ks := filterOutput(c.state)
		// Output bit = ks XOR input_bit.
		ibit := uint32((input >> i) & 1)
		nrbit := uint32((nr >> i) & 1)
		out |= (uint32(ks) ^ ibit) << i
		// Feedback: state advance with (LFSR-feedback XOR (input^nr)) bit
		// fed into bit 47.
		fb := feedbackBit(c.state) ^ uint64(ibit^nrbit)
		c.state = (c.state >> 1) | (fb << 47)
	}
	return out
}

// CryptFeedback runs the cipher exactly like Crypt but feeds each input
// bit (LSB-first) into the LFSR's high position alongside the natural
// feedback. Used during the MIFARE Classic auth nT phase, where the
// tag nonce mixes into the cipher state. Returns the keystream
// produced (caller almost always discards it; the side effect on
// state is the point).
func (c *Cipher) CryptFeedback(in uint32) uint32 {
	var ks uint32
	for i := uint(0); i < 32; i++ {
		ks |= uint32(filterOutput(c.state)) << i
		fb := feedbackBit(c.state) ^ uint64((in>>i)&1)
		c.state = (c.state >> 1) | (fb << 47)
	}
	return ks
}

// Prng advances the MIFARE Classic tag PRNG forward n cycles from the
// 32-bit seed `from`. The hardware PRNG is two 16-bit LFSRs in
// lockstep (polynomial x^16 + x^14 + x^13 + x^11 + 1 per half) whose
// outputs are concatenated into the 32-bit nT value.
//
// Per-cycle: the high half advances (its low bit shifts out, new bit
// computed from taps); the low half is the high half's previous value.
// This is the equivalent of mfoc's `prng_successor` with byte-swapped
// representation.
func Prng(from uint32, n int) uint32 {
	// LSB-first internal layout. The wire form is byte-swapped (big-
	// endian); we accept and emit the wire form here for caller
	// convenience.
	x := byteSwap32(from)
	for i := 0; i < n; i++ {
		// Compute new bit from taps at positions 0, 2, 3, 5
		// (corresponding to x^16+x^14+x^13+x^11+1 with index from
		// the LSB of the 16-bit half).
		newBit := uint32(((x >> 16) ^ (x >> 18) ^ (x >> 19) ^ (x >> 21)) & 1)
		x = (x >> 1) | (newBit << 31)
	}
	return byteSwap32(x)
}

// byteSwap32 reverses the byte order of a uint32. Used at the Prng
// boundaries to convert between the wire MIFARE form and the internal
// LSB-first LFSR layout.
func byteSwap32(v uint32) uint32 {
	return (v>>24)&0xFF |
		((v>>8)&0xFF00) |
		((v<<8)&0xFF0000) |
		(v<<24)&0xFF000000
}

// clockLFSR advances the LFSR a single step. extBit is XOR'd into the
// natural feedback before shifting (pass 0 for the no-external-input
// case). Returns the keystream bit produced before the shift.
//
// Exposed unexported so the same-package mfkey32 rollback / verification
// helpers can step deterministically without going through Crypt's
// 32-bit batch.
func (c *Cipher) clockLFSR(extBit uint64) uint64 {
	ks := filterOutput(c.state)
	fb := feedbackBit(c.state) ^ (extBit & 1)
	c.state = (c.state >> 1) | (fb << 47)
	return ks
}

// --- Internal LFSR helpers -------------------------------------------

// lfsr48bit returns bit n of the 48-bit LFSR state as 0 or 1.
func lfsr48bit(state uint64, n int) uint64 {
	return (state >> uint(n)) & 1
}

// feedbackBit returns the LFSR's natural feedback bit for the next
// shift, computed as the XOR of taps at lfsrTaps positions.
func feedbackBit(state uint64) uint64 {
	var fb uint64
	for _, t := range lfsrTaps {
		fb ^= lfsr48bit(state, t)
	}
	return fb
}

// fa, fb, fc — Crypto1 nonlinear filter components.
//
// fa, fb take 4 input bits each, fc takes 5 (the outputs of two fa's
// and three fb's combined). All operations are over GF(2): & is AND,
// | is OR, ^ is XOR. Inputs are 0/1 — masking ensures we don't carry
// extra bits.

func fa(a, b, c, d uint64) uint64 {
	a &= 1
	b &= 1
	c &= 1
	d &= 1
	return ((a | b) ^ (a & d)) ^ (c & ((a ^ b) | d))
}

func fb(a, b, c, d uint64) uint64 {
	a &= 1
	b &= 1
	c &= 1
	d &= 1
	return ((a & b) | c) ^ ((a ^ b) & (c | d))
}

func fc(a, b, c, d, e uint64) uint64 {
	a &= 1
	b &= 1
	c &= 1
	d &= 1
	e &= 1
	return (a | ((b | e) & (d ^ e))) ^ ((a ^ (b & d)) & ((c ^ d) | (b & e)))
}

// filterOutput returns the keystream bit produced by the current LFSR
// state, computed by combining selected taps through fa/fb/fc per
// Garcia et al. §3.3.
//
// Tap arrangement (from the paper):
//
//	y0 = fa(s9, s11, s13, s15)
//	y1 = fb(s17, s19, s21, s23)
//	y2 = fb(s25, s27, s29, s31)
//	y3 = fa(s33, s35, s37, s39)
//	y4 = fb(s41, s43, s45, s47)
//	output = fc(y0, y1, y2, y3, y4)
func filterOutput(state uint64) uint64 {
	y0 := fa(lfsr48bit(state, 9), lfsr48bit(state, 11), lfsr48bit(state, 13), lfsr48bit(state, 15))
	y1 := fb(lfsr48bit(state, 17), lfsr48bit(state, 19), lfsr48bit(state, 21), lfsr48bit(state, 23))
	y2 := fb(lfsr48bit(state, 25), lfsr48bit(state, 27), lfsr48bit(state, 29), lfsr48bit(state, 31))
	y3 := fa(lfsr48bit(state, 33), lfsr48bit(state, 35), lfsr48bit(state, 37), lfsr48bit(state, 39))
	y4 := fb(lfsr48bit(state, 41), lfsr48bit(state, 43), lfsr48bit(state, 45), lfsr48bit(state, 47))
	return fc(y0, y1, y2, y3, y4)
}
