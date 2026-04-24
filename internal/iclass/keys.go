package iclass

import (
	"crypto/des" //nolint:gosec // DES is the algorithm specified by iCLASS Elite
	"encoding/binary"
	"fmt"
)

// ─────────────────────────────────────────────────────────────────────────────
// Key permutation: iClass ↔ NIST standard DES key format
// (from García et al. ESORICS 2012 and Meriac 27C3 2010)
// ─────────────────────────────────────────────────────────────────────────────

// PermuteKey converts a key from NIST/standard DES format to iClass internal
// format by transposing the 8×8 bit matrix (row i of output = column i of input).
// permutekey() in the holiman/loclass reference.
func PermuteKey(key [8]byte) [8]byte {
	var out [8]byte
	for j := 0; j < 8; j++ {
		for k := 0; k < 8; k++ {
			// out[j] bit k = bit(7-j) of key[k]
			// Derived from permutekey() in García et al. reference: inverse of PermuteKeyRev.
			bit := (key[k] >> uint(7-j)) & 1
			out[j] |= bit << uint(k)
		}
	}
	return out
}

// PermuteKeyRev converts a key from iClass internal format to NIST/standard
// DES format (inverse of PermuteKey). permutekey_rev() in the reference.
func PermuteKeyRev(key [8]byte) [8]byte {
	var out [8]byte
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			bit := (key[j] >> uint(7-i)) & 1
			out[7-i] |= bit << uint(7-j)
		}
	}
	return out
}

// desEncryptStd encrypts one 8-byte block with a standard-format DES key.
func desEncryptStd(key, block [8]byte) ([8]byte, error) {
	c, err := des.NewCipher(key[:]) //nolint:gosec // algorithm-required DES use
	if err != nil {
		return [8]byte{}, fmt.Errorf("DES NewCipher: %w", err)
	}
	var out [8]byte
	c.Encrypt(out[:], block[:])
	return out, nil
}

// desDecryptStd decrypts one 8-byte block with a standard-format DES key.
func desDecryptStd(key, block [8]byte) ([8]byte, error) {
	c, err := des.NewCipher(key[:]) //nolint:gosec // algorithm-required DES use
	if err != nil {
		return [8]byte{}, fmt.Errorf("DES NewCipher: %w", err)
	}
	var out [8]byte
	c.Decrypt(out[:], block[:])
	return out, nil
}

// desEncryptIClass encrypts a block using a key in iClass internal format.
// It converts the key to standard DES format first.
func desEncryptIClass(iclassKey, block [8]byte) ([8]byte, error) {
	stdKey := PermuteKeyRev(iclassKey)
	return desEncryptStd(stdKey, block)
}

// desDecryptIClass decrypts a block using a key in iClass internal format.
func desDecryptIClass(iclassKey, block [8]byte) ([8]byte, error) {
	stdKey := PermuteKeyRev(iclassKey)
	return desDecryptStd(stdKey, block)
}

// ─────────────────────────────────────────────────────────────────────────────
// RotateKey: rk function from the loclass attack
// ─────────────────────────────────────────────────────────────────────────────

// rotateLeft8 rotates an 8-bit value left by 1.
func rotateLeft8(v uint8) uint8 {
	return (v << 1) | (v >> 7)
}

// rotateRight8 rotates an 8-bit value right by 1.
func rotateRight8(v uint8) uint8 {
	return (v >> 1) | (v << 7)
}

// rotateKey applies n left-rotations (each 1 bit) to all 8 bytes of key.
// (rk function, Definition 14 of García et al.)
func rotateKey(key [8]byte, n int) [8]byte {
	out := key
	for i := 0; i < n; i++ {
		for j := 0; j < 8; j++ {
			out[j] = rotateLeft8(out[j])
		}
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// hash0: Standard Security key diversification
// (hash0, Definition 11, García et al. ESORICS 2012 §4)
// ─────────────────────────────────────────────────────────────────────────────

// piTable is the 35-element lookup table used in hash0.
// Source: ikeys.c in the loclass/proxmark3 reference code, which derives it
// from the algorithm described in García et al. These constants are
// algorithm-specification values, not copyrightable expression.
var piTable = [35]uint8{
	0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D, 0x2E,
	0x33, 0x35, 0x39, 0x36, 0x3A, 0x3C, 0x47, 0x4B, 0x4D,
	0x4E, 0x53, 0x55, 0x56, 0x59, 0x5A, 0x5C, 0x63, 0x65,
	0x66, 0x69, 0x6A, 0x6C, 0x71, 0x72, 0x74, 0x78,
}

// getSixBit extracts the n-th 6-bit value from a packed 64-bit word.
// Layout: [x:8][y:8][z0:6][z1:6]...[z7:6] (MSB-first).
func getSixBit(c uint64, n int) uint8 {
	return uint8((c >> (42 - 6*n)) & 0x3F)
}

// putSixBit stores a 6-bit value at position n in a packed 64-bit word.
func putSixBit(c *uint64, z uint8, n int) {
	shift := uint(42 - 6*n)
	mask := uint64(0x3F) << shift
	*c = (*c &^ mask) | (uint64(z&0x3F) << shift)
}

// swapZValues reverses the order of z[0..7] in a packed c word while keeping
// x and y unchanged.
func swapZValues(c uint64) uint64 {
	var out uint64
	for i := 0; i < 8; i++ {
		putSixBit(&out, getSixBit(c, i), 7-i)
	}
	out |= c & 0xFFFF000000000000 // preserve x and y
	return out
}

// ck ensures uniqueness among z[0..3] positions i and j by replacing z[i]
// with the value j if they are equal. (ck function, García et al.)
func ck(i, j int, z uint64) uint64 {
	if i == 1 && j == -1 {
		return z
	}
	if j == -1 {
		return ck(i-1, i-2, z)
	}
	if getSixBit(z, i) == getSixBit(z, j) {
		var newz uint64
		for c := 0; c < 4; c++ {
			if c == i {
				putSixBit(&newz, uint8(j), c) //nolint:gosec // j is 0..3
			} else {
				putSixBit(&newz, getSixBit(z, c), c)
			}
		}
		return ck(i, j-1, newz)
	}
	return ck(i, j-1, z)
}

// check deduplicates z[0..3] and z[4..7] independently using ck.
func check(z uint64) uint64 {
	ck1 := ck(3, 2, z) & 0x0000FFFFFF000000
	ck2 := ck(3, 2, z<<24) & 0x0000FFFFFF000000
	return ck1 | (ck2 >> 24)
}

// permuteHash selects 8 six-bit values from zCaret according to the 8-bit
// mask p, alternating between "left" (z[l]+1) and "right" (z[r]) positions.
// This is the `permute` function in ikeys.c, processed bit 0 → bit 7 of p.
func permuteHash(p uint8, zCaret uint64) uint64 {
	var out uint64
	l, r := 0, 4
	for bit := 0; bit < 8; bit++ {
		if (p>>uint(bit))&1 == 1 {
			// pn = 1: use z[l]+1, advance l
			val := getSixBit(zCaret, l) + 1
			putSixBit(&out, val, bit)
			l++
		} else {
			// pn = 0: use z[r], advance r
			val := getSixBit(zCaret, r)
			putSixBit(&out, val, bit)
			r++
		}
	}
	// Shift to canonical positions (bits 47..0)
	return out
}

// Hash0 computes the iCLASS key diversification function hash0.
// Input c is the big-endian uint64 of an 8-byte DES-encrypted CSN.
// Output is the 8-byte diversified key.
// (Definition 11, García et al. ESORICS 2012.)
func Hash0(c uint64) [8]byte {
	c = swapZValues(c)

	x := uint8(c >> 56)
	y := uint8(c >> 48)

	// Apply z'[i] = (z[i] mod (63-i)) + i  for i in 0..3
	// and  z'[i+4] = (z[i+4] mod (64-i)) + i  for i in 0..3
	var zP uint64
	for n := 0; n < 4; n++ {
		zn := getSixBit(c, n)
		zn4 := getSixBit(c, n+4)
		putSixBit(&zP, uint8(int(zn)%(63-n))+uint8(n), n)    //nolint:gosec // n in [0,3]
		putSixBit(&zP, uint8(int(zn4)%(64-n))+uint8(n), n+4) //nolint:gosec
	}

	zCaret := check(zP)

	p := piTable[x%35]
	if x&1 != 0 { // x7 = 1
		p = ^p
	}

	zTilde := permuteHash(p, zCaret)

	var k [8]byte
	for i := 0; i < 8; i++ {
		// yBit = bit i of y (not bit 7-i): (y << (7-i)) & 0x80 from the C reference
		yBit := (y >> uint(i)) & 1
		zVal := getSixBit(zTilde, i) << 1 // 6-bit value, shifted to bits 6..1
		pBit := (p >> uint(i)) & 1
		k[i] = yBit << 7 // place y_bit at MSB
		if yBit == 1 {
			k[i] |= (^zVal) & 0x7E
			k[i] |= pBit & 1
			k[i]++
		} else {
			k[i] |= zVal & 0x7E
			k[i] |= (^pBit) & 1
		}
	}
	return k
}

// DiversifyKey derives the per-card iCLASS key by computing
// hash0(DES_enc(key_std, csn)), where key_std is the standard-format master key.
// (García et al. §3 — "k = hash0(DES_enc(id, K))".)
func DiversifyKey(csn [8]byte, keyStd [8]byte) ([8]byte, error) {
	enc, err := desEncryptStd(keyStd, csn)
	if err != nil {
		return [8]byte{}, err
	}
	cryptedCSN := binary.BigEndian.Uint64(enc[:])
	return Hash0(cryptedCSN), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// hash1: CSN → keytable-index selector
// (from García et al. §5 and Swende 2014)
// ─────────────────────────────────────────────────────────────────────────────

// Hash1 computes the 8 keytable indices for a given CSN.
// Each output byte is in [0, 127] (high bit cleared).
func Hash1(csn [8]byte) [8]byte {
	var k [8]byte
	k[0] = csn[0] ^ csn[1] ^ csn[2] ^ csn[3] ^ csn[4] ^ csn[5] ^ csn[6] ^ csn[7]
	k[1] = csn[0] + csn[1] + csn[2] + csn[3] + csn[4] + csn[5] + csn[6] + csn[7]
	k[2] = rotateRight8(nibbleSwap(csn[2] + k[1]))
	k[3] = rotateLeft8(nibbleSwap(csn[3] + k[0]))
	k[4] = ^rotateRight8(csn[4]+k[2]) + 1
	k[5] = ^rotateLeft8(csn[5]+k[3]) + 1
	k[6] = rotateRight8(csn[6] + (k[4] ^ 0x3c))
	k[7] = rotateLeft8(csn[7] + (k[5] ^ 0xc3))
	for i := 0; i < 8; i++ {
		k[i] &= 0x7F
	}
	return k
}

// nibbleSwap swaps the high and low nibbles of a byte.
func nibbleSwap(v uint8) uint8 {
	return (v >> 4) | (v << 4)
}

// ─────────────────────────────────────────────────────────────────────────────
// hash2: Elite keytable derivation and inversion
// (Definition 15, García et al. ESORICS 2012.)
// ─────────────────────────────────────────────────────────────────────────────

// Hash2 derives the 128-byte iCLASS Elite high-security keytable from
// the 8-byte custom master key Kcus (in iClass internal format).
//
// Layout: keytable[i*16..i*16+7] = y[i], keytable[i*16+8..i*16+15] = z[i].
func Hash2(kcus [8]byte) ([128]byte, error) {
	// key64_negated = ~kcus
	var neg [8]byte
	for i := range neg {
		neg[i] = ^kcus[i]
	}

	// z[0] = DES_enc_iclass(kcus, ~kcus)
	var z [8][8]byte
	var y [8][8]byte

	z0, err := desEncryptIClass(kcus, neg)
	if err != nil {
		return [128]byte{}, err
	}
	z[0] = z0

	// y[0] = DES_dec_iclass(z[0], ~kcus)
	y0, err := desDecryptIClass(z[0], neg)
	if err != nil {
		return [128]byte{}, err
	}
	y[0] = y0

	for i := 1; i < 8; i++ {
		rk := rotateKey(kcus, i)
		// z[i] = DES_dec_iclass(rk, z[i-1])
		zi, err := desDecryptIClass(rk, z[i-1])
		if err != nil {
			return [128]byte{}, err
		}
		z[i] = zi
		// y[i] = DES_enc_iclass(rk, y[i-1])
		yi, err := desEncryptIClass(rk, y[i-1])
		if err != nil {
			return [128]byte{}, err
		}
		y[i] = yi
	}

	var kt [128]byte
	for i := 0; i < 8; i++ {
		copy(kt[i*16:i*16+8], y[i][:])
		copy(kt[i*16+8:i*16+16], z[i][:])
	}
	return kt, nil
}

// InvertHash2 recovers the 8-byte Kcus from the first 16 bytes of the
// Elite keytable (y[0] || z[0]).
//
// From the paper: K_cus = ~DES_enc(permutekey_rev(z[0]), y[0])
func InvertHash2(first16 [16]byte) ([8]byte, error) {
	var y0, z0 [8]byte
	copy(y0[:], first16[:8])
	copy(z0[:], first16[8:16])

	// z0 is in iClass format; convert to standard for DES
	z0Std := PermuteKeyRev(z0)

	// ~K_cus = DES_enc(z0_std, y0)
	negKcus, err := desEncryptStd(z0Std, y0)
	if err != nil {
		return [8]byte{}, err
	}

	var kcus [8]byte
	for i := range kcus {
		kcus[i] = ^negKcus[i]
	}
	return kcus, nil
}

// StandardMasterKeyAA0 is the globally-shared iCLASS Standard Security
// debit (AA1) master key, published by Meriac at 27C3 (2010) and confirmed
// by independent researchers. Every Standard-Security-keyed card at every
// site uses this. Not a secret — it is ubiquitous public information.
var StandardMasterKeyAA0 = [8]byte{0xAE, 0xA6, 0x84, 0xA6, 0xDA, 0xB2, 0x32, 0x78}
