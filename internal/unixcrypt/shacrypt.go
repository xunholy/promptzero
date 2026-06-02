// SPDX-License-Identifier: AGPL-3.0-or-later

package unixcrypt

import (
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"strconv"
	"strings"
)

// SHA-crypt magic prefixes and round bounds (Ulrich Drepper's scheme; the
// modern Linux /etc/shadow format — $6$ sha512crypt is the common default).
const (
	MagicSHA256 = "$5$"
	MagicSHA512 = "$6$"

	roundsDefault = 5000
	roundsMin     = 1000
	roundsMax     = 999999999
	saltMaxSHA    = 16
)

// b64group names the three digest-byte indices (-1 → a zero byte) and the output
// length for one step of the SHA-crypt final base64 permutation.
type b64group struct{ i2, i1, i0, n int }

// sha512Perm / sha256Perm are the digest-byte orderings from the SHA-crypt spec.
var sha512Perm = []b64group{
	{0, 21, 42, 4}, {22, 43, 1, 4}, {44, 2, 23, 4}, {3, 24, 45, 4}, {25, 46, 4, 4},
	{47, 5, 26, 4}, {6, 27, 48, 4}, {28, 49, 7, 4}, {50, 8, 29, 4}, {9, 30, 51, 4},
	{31, 52, 10, 4}, {53, 11, 32, 4}, {12, 33, 54, 4}, {34, 55, 13, 4}, {56, 14, 35, 4},
	{15, 36, 57, 4}, {37, 58, 16, 4}, {59, 17, 38, 4}, {18, 39, 60, 4}, {40, 61, 19, 4},
	{62, 20, 41, 4}, {-1, -1, 63, 2},
}

var sha256Perm = []b64group{
	{0, 10, 20, 4}, {21, 1, 11, 4}, {12, 22, 2, 4}, {3, 13, 23, 4}, {24, 4, 14, 4},
	{15, 25, 5, 4}, {6, 16, 26, 4}, {27, 7, 17, 4}, {18, 28, 8, 4}, {9, 19, 29, 4},
	{-1, 31, 30, 3},
}

// SHA256Crypt computes a sha256crypt ($5$) hash. rounds <= 0 selects the default
// (5000, with no rounds= prefix); otherwise it is clamped to [1000, 999999999]
// and echoed as rounds=N$ in the output.
func SHA256Crypt(password, salt string, rounds int) string {
	r, emit := normRounds(rounds)
	return shaCrypt(password, salt, r, emit, MagicSHA256, sha256.New, sha256Perm)
}

// SHA512Crypt computes a sha512crypt ($6$) hash (see SHA256Crypt for rounds).
func SHA512Crypt(password, salt string, rounds int) string {
	r, emit := normRounds(rounds)
	return shaCrypt(password, salt, r, emit, MagicSHA512, sha512.New, sha512Perm)
}

func normRounds(rounds int) (int, bool) {
	if rounds <= 0 {
		return roundsDefault, false
	}
	return clampRounds(rounds), true
}

func clampRounds(r int) int {
	switch {
	case r < roundsMin:
		return roundsMin
	case r > roundsMax:
		return roundsMax
	default:
		return r
	}
}

// shaCrypt is the Drepper SHA-crypt algorithm, parameterised by hash and the
// final permutation. salt is truncated to 16 bytes (and at any '$').
func shaCrypt(password, saltRaw string, rounds int, emitRounds bool, magic string, newHash func() hash.Hash, perm []b64group) string {
	key := []byte(password)
	if i := strings.IndexByte(saltRaw, '$'); i >= 0 {
		saltRaw = saltRaw[:i]
	}
	if len(saltRaw) > saltMaxSHA {
		saltRaw = saltRaw[:saltMaxSHA]
	}
	salt := []byte(saltRaw)
	keyLen, saltLen := len(key), len(salt)

	// Digest B = H(key || salt || key).
	b := newHash()
	b.Write(key)
	b.Write(salt)
	b.Write(key)
	sumB := b.Sum(nil)
	dsize := len(sumB)

	// Digest A.
	a := newHash()
	a.Write(key)
	a.Write(salt)
	for i := keyLen; i > 0; i -= dsize {
		n := dsize
		if i < dsize {
			n = i
		}
		a.Write(sumB[:n])
	}
	for i := keyLen; i > 0; i >>= 1 {
		if i&1 != 0 {
			a.Write(sumB)
		} else {
			a.Write(key)
		}
	}
	sumA := a.Sum(nil)

	// P sequence = (H(key * keyLen)) repeated to keyLen bytes.
	dp := newHash()
	for i := 0; i < keyLen; i++ {
		dp.Write(key)
	}
	p := repeatTo(dp.Sum(nil), keyLen)

	// S sequence = (H(salt * (16 + sumA[0]))) repeated to saltLen bytes.
	ds := newHash()
	for i := 0; i < 16+int(sumA[0]); i++ {
		ds.Write(salt)
	}
	s := repeatTo(ds.Sum(nil), saltLen)

	// Main strengthening loop.
	cur := sumA
	for i := 0; i < rounds; i++ {
		c := newHash()
		if i&1 != 0 {
			c.Write(p)
		} else {
			c.Write(cur)
		}
		if i%3 != 0 {
			c.Write(s)
		}
		if i%7 != 0 {
			c.Write(p)
		}
		if i&1 != 0 {
			c.Write(cur)
		} else {
			c.Write(p)
		}
		cur = c.Sum(nil)
	}

	var out strings.Builder
	out.WriteString(magic)
	if emitRounds {
		out.WriteString("rounds=")
		out.WriteString(strconv.Itoa(rounds))
		out.WriteByte('$')
	}
	out.WriteString(saltRaw)
	out.WriteByte('$')
	at := func(i int) uint32 {
		if i < 0 {
			return 0
		}
		return uint32(cur[i])
	}
	for _, g := range perm {
		out.WriteString(to64(at(g.i2)<<16|at(g.i1)<<8|at(g.i0), g.n))
	}
	return out.String()
}

// repeatTo returns n bytes formed by repeating d.
func repeatTo(d []byte, n int) []byte {
	out := make([]byte, 0, n)
	for len(out) < n {
		take := len(d)
		if take > n-len(out) {
			take = n - len(out)
		}
		out = append(out, d[:take]...)
	}
	return out
}

// verifySHA recomputes a $5$/$6$ hash from the rounds+salt parsed out of it.
func verifySHA(password, hash, magic string, newHash func() hash.Hash, perm []b64group) string {
	rest := hash[len(magic):]
	rounds, emit := roundsDefault, false
	if strings.HasPrefix(rest, "rounds=") {
		rest = rest[len("rounds="):]
		if i := strings.IndexByte(rest, '$'); i >= 0 {
			if n, err := strconv.Atoi(rest[:i]); err == nil {
				rounds, emit = clampRounds(n), true
			}
			rest = rest[i+1:]
		}
	}
	salt := rest
	if i := strings.IndexByte(rest, '$'); i >= 0 {
		salt = rest[:i]
	}
	return shaCrypt(password, salt, rounds, emit, magic, newHash, perm)
}
