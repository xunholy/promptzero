// SPDX-License-Identifier: AGPL-3.0-or-later

// Package unixcrypt implements the MD5-based crypt(3) password hashes: the
// FreeBSD/Linux md5crypt ($1$) and the Apache apr1 ($apr1$) variant. It is an
// offline credential primitive: compute the hash of a candidate password, or
// verify a candidate against a captured hash. The same $1$ algorithm is Cisco
// IOS "type 5"; $apr1$ is the Apache htpasswd format. It complements the
// credential toolkit — hash_identify recognises these hashes (hashcat 500 / 1600)
// and hash_crack attacks them, but neither could produce or check one. Pure
// offline compute from operator-supplied strings; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. md5crypt is Poul-Henning Kamp's algorithm: an MD5 digest scrambled
// over 1000 rounds with a salt, then a custom base64. It is built on the
// standard library's crypto/md5; there is nothing to wrap (the only third-party
// option would be a crypt(3) cgo binding or golang.org/x/crypto/... — neither is
// warranted for ~60 lines), consistent with internal/nthash and internal/wpa.
//
// # Verifiable / no confidently-wrong output
//
// Strong verification class. The hashes are gated against vectors produced by an
// independent oracle (OpenSSL `passwd -1` / `passwd -apr1`) across several
// password and salt lengths (including the empty password and a 16-character
// password), so the algorithm ships only if it matches the reference byte for
// byte.
//
// # Covered / deferred
//
// Covered: md5crypt ($1$, also Cisco type 5) and apr1 ($apr1$), both compute and
// verify. Deferred: the SHA-crypt family ($5$ sha256crypt, $6$ sha512crypt) —
// they share this structure but with configurable rounds and a more elaborate
// permutation; a clean follow-up, left out here to keep this unit fully verified.
package unixcrypt

import (
	"crypto/md5" //nolint:gosec // md5crypt is MD5 by the crypt(3) spec; this is the algorithm, not a security choice.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"strings"
)

// Magic prefixes.
const (
	MagicMD5  = "$1$"
	MagicAPR1 = "$apr1$"
)

// itoa64 is the crypt(3) base64 alphabet (note: not standard base64 order).
const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func to64(v uint32, n int) string {
	var b strings.Builder
	for ; n > 0; n-- {
		b.WriteByte(itoa64[v&0x3f])
		v >>= 6
	}
	return b.String()
}

// MD5Crypt computes the md5crypt ($1$) hash of password with the given salt.
func MD5Crypt(password, salt string) string { return core(password, salt, MagicMD5) }

// APR1 computes the Apache apr1 ($apr1$) hash of password with the given salt.
func APR1(password, salt string) string { return core(password, salt, MagicAPR1) }

// normaliseSalt truncates a salt at the first '$' and to 8 characters, matching
// crypt(3).
func normaliseSalt(salt string) string {
	if i := strings.IndexByte(salt, '$'); i >= 0 {
		salt = salt[:i]
	}
	if len(salt) > 8 {
		salt = salt[:8]
	}
	return salt
}

// core is the Poul-Henning Kamp MD5-crypt algorithm, parameterised by magic.
func core(password, salt, magic string) string {
	pw := []byte(password)
	salt = normaliseSalt(salt)
	sp := []byte(salt)

	// Alternate sum: MD5(password || salt || password).
	altInput := make([]byte, 0, len(pw)*2+len(sp))
	altInput = append(altInput, pw...)
	altInput = append(altInput, sp...)
	altInput = append(altInput, pw...)
	alt := md5.Sum(altInput)

	h := md5.New()
	h.Write(pw)
	h.Write([]byte(magic))
	h.Write(sp)
	// Append the alternate sum, len(password) bytes, cycling in 16-byte chunks.
	for i := len(pw); i > 0; i -= 16 {
		n := 16
		if i < 16 {
			n = i
		}
		h.Write(alt[:n])
	}
	// "Something really weird": for each bit of len(password), high→low, add a
	// NUL byte when the bit is set, else the first byte of the password.
	for i := len(pw); i != 0; i >>= 1 {
		if i&1 != 0 {
			h.Write([]byte{0})
		} else {
			h.Write(pw[:1])
		}
	}
	final := h.Sum(nil)

	// 1000 rounds of re-hashing with a fixed permutation of password/salt/final.
	for i := 0; i < 1000; i++ {
		c := md5.New()
		if i&1 != 0 {
			c.Write(pw)
		} else {
			c.Write(final)
		}
		if i%3 != 0 {
			c.Write(sp)
		}
		if i%7 != 0 {
			c.Write(pw)
		}
		if i&1 != 0 {
			c.Write(final)
		} else {
			c.Write(pw)
		}
		final = c.Sum(nil)
	}

	var out strings.Builder
	out.WriteString(magic)
	out.WriteString(salt)
	out.WriteByte('$')
	out.WriteString(to64(uint32(final[0])<<16|uint32(final[6])<<8|uint32(final[12]), 4))
	out.WriteString(to64(uint32(final[1])<<16|uint32(final[7])<<8|uint32(final[13]), 4))
	out.WriteString(to64(uint32(final[2])<<16|uint32(final[8])<<8|uint32(final[14]), 4))
	out.WriteString(to64(uint32(final[3])<<16|uint32(final[9])<<8|uint32(final[15]), 4))
	out.WriteString(to64(uint32(final[4])<<16|uint32(final[10])<<8|uint32(final[5]), 4))
	out.WriteString(to64(uint32(final[11]), 2))
	return out.String()
}

// Scheme returns a human label for a hash's magic prefix.
func Scheme(hash string) string {
	switch {
	case strings.HasPrefix(hash, MagicAPR1):
		return "apr1"
	case strings.HasPrefix(hash, MagicMD5):
		return "md5crypt"
	case strings.HasPrefix(hash, MagicSHA512):
		return "sha512crypt"
	case strings.HasPrefix(hash, MagicSHA256):
		return "sha256crypt"
	default:
		return ""
	}
}

// Verify recomputes the hash of password from the scheme and salt parsed out of
// an existing crypt(3) hash ($1$ md5crypt, $apr1$, $5$ sha256crypt, or $6$
// sha512crypt) and constant-time-compares it.
func Verify(password, hash string) (bool, error) {
	var got string
	switch {
	case strings.HasPrefix(hash, MagicAPR1):
		got = verifyMD5(password, hash, MagicAPR1)
	case strings.HasPrefix(hash, MagicSHA512):
		got = verifySHA(password, hash, MagicSHA512, sha512.New, sha512Perm)
	case strings.HasPrefix(hash, MagicSHA256):
		got = verifySHA(password, hash, MagicSHA256, sha256.New, sha256Perm)
	case strings.HasPrefix(hash, MagicMD5):
		got = verifyMD5(password, hash, MagicMD5)
	default:
		return false, fmt.Errorf("unixcrypt: unrecognised hash (expected $1$, $apr1$, $5$ or $6$)")
	}
	if got == "" {
		return false, fmt.Errorf("unixcrypt: malformed hash (no salt delimiter)")
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1, nil
}

// verifyMD5 recomputes an md5crypt/apr1 hash from its parsed salt.
func verifyMD5(password, hash, magic string) string {
	rest := hash[len(magic):]
	i := strings.IndexByte(rest, '$')
	if i < 0 {
		return ""
	}
	return core(password, rest[:i], magic)
}
