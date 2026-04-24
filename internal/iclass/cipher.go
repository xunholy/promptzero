// Package iclass implements the iCLASS block cipher and the loclass
// key-recovery attack against HID iCLASS Elite / High Security readers.
//
// Algorithm derivation: Garcia, de Koning Gans, Verdult, Meriac —
// "Dismantling iClass and iClass Elite", ESORICS 2012, LNCS vol. 7459.
// Meriac — "Heart of Darkness", 27C3 (2010).
// Swende — "Elite iClass Hacking", swende.se blog (2014).
//
// License posture: clean-reimpl. Algorithm derived from the published
// academic papers above. No source code from iceman/proxmark3 (GPLv2) or
// holiman/loclass (GPLv2) was copied verbatim. Sub-primitive test vectors
// are public facts about the algorithm.
package iclass

// State is the 40-bit iCLASS stream-cipher state, as defined in
// Definition 1 of García et al. ESORICS 2012.
// Components:
//   - l, r: 8-bit left/right registers
//   - b: 8-bit bottom register
//   - t: 16-bit top register (LFSR)
type State struct {
	l, r, b uint8
	t       uint16
}

// InitState returns the initial cipher state for the given 8-byte key,
// per Definition 6 of García et al. ESORICS 2012.
func InitState(k [8]byte) State {
	return State{
		l: (k[0] ^ 0x4c + 0xec) & 0xff,
		r: (k[0] ^ 0x4c + 0x21) & 0xff,
		b: 0x4c,
		t: 0xe012,
	}
}

// tFeedback computes the T feedback function for the top register.
// T(t) = t[15] ⊕ t[14] ⊕ t[10] ⊕ t[8] ⊕ t[5] ⊕ t[4] ⊕ t[1] ⊕ t[0]
// (Definition 2, García et al. ESORICS 2012; bit 15 = MSB.)
func tFeedback(t uint16) uint8 {
	return uint8(t>>15) ^ uint8(t>>14) ^ uint8(t>>10) ^ uint8(t>>8) ^
		uint8(t>>5) ^ uint8(t>>4) ^ uint8(t>>1) ^ uint8(t)&1
}

// bFeedback computes the B feedback function for the bottom register.
// B(b) = b[6] ⊕ b[5] ⊕ b[4] ⊕ b[0]
// (Definition 2, García et al. ESORICS 2012; bit 7 = MSB.)
func bFeedback(b uint8) uint8 {
	return ((b >> 6) ^ (b >> 5) ^ (b >> 4) ^ b) & 1
}

// selectIdx returns the 3-bit key-byte selector index from (x, y, r),
// where x = T(t), y = input bit, r = right register.
// (Definition 3, García et al. ESORICS 2012.)
func selectIdx(x, y, r uint8) uint8 {
	r0 := (r >> 7) & 1
	r1 := (r >> 6) & 1
	r2 := (r >> 5) & 1
	r3 := (r >> 4) & 1
	r4 := (r >> 3) & 1
	r5 := (r >> 2) & 1
	r6 := (r >> 1) & 1
	r7 := r & 1

	z0 := (r0 & r2) ^ (r1 & (r3 ^ 1)) ^ (r2 | r4)
	z1 := (r0 | r2) ^ (r5 | r7) ^ r1 ^ r6 ^ x ^ y
	z2 := (r3 & (r5 ^ 1)) ^ (r4 & r6) ^ r7 ^ x
	return ((z0 & 1) << 2) | ((z1 & 1) << 1) | (z2 & 1)
}

// Successor advances the cipher by one clock given key k and input bit y.
// (Definition 4, García et al. ESORICS 2012.)
func (s State) Successor(k [8]byte, y uint8) State {
	Tt := tFeedback(s.t) & 1
	r0 := (s.r >> 7) & 1
	r4 := (s.r >> 3) & 1
	r7 := s.r & 1

	var ns State
	ns.t = (s.t >> 1) | (uint16(Tt^r0^r4) << 15)
	ns.b = (s.b >> 1) | ((bFeedback(s.b) ^ r7) << 7)

	keyByte := k[selectIdx(Tt, y, s.r)]
	ns.r = keyByte ^ ns.b + s.l // modular uint8 arithmetic
	ns.l = ns.r + s.r
	return ns
}

// OutputBit returns the cipher output bit from state s.
// The output is bit 2 of the r register (Definition 5, García et al.).
func (s State) OutputBit() uint8 {
	return (s.r >> 2) & 1
}

// DoReaderMAC computes the 4-byte iCLASS reader MAC over the 12-byte
// challenge ccNR = CC(8) || NR(4), using the diversified key divKey.
//
// Processing order: each input byte is fed LSB-first. Output bits are
// collected LSB-first into the 4-byte MAC. This matches the
// opt_doReaderMAC / doReaderMAC implementations in the reference code.
func DoReaderMAC(ccNR [12]byte, divKey [8]byte) [4]byte {
	s := InitState(divKey)

	// Feed each input byte LSB-first (bit 0 first).
	for _, b := range ccNR {
		for j := uint(0); j < 8; j++ {
			bit := (b >> j) & 1
			s = s.Successor(divKey, bit)
		}
	}

	// Collect 32 output bits into 4 bytes, LSB-first per byte.
	// For each bit: sample OutputBit then clock with y=0.
	var mac [4]byte
	for byteIdx := 0; byteIdx < 4; byteIdx++ {
		var out byte
		for bitIdx := uint(0); bitIdx < 8; bitIdx++ {
			out |= s.OutputBit() << bitIdx
			s = s.Successor(divKey, 0)
		}
		mac[byteIdx] = out
	}
	return mac
}
