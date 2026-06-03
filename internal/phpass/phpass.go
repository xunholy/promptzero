// SPDX-License-Identifier: AGPL-3.0-or-later

// Package phpass verifies and computes "portable PHP" password hashes — the
// phpass scheme used by WordPress ($P$…) and phpBB3 ($H$…). WordPress is the
// most-deployed CMS, so its user-table hashes are among the most common offline-
// crack targets (hashcat mode 400); this is the compute/verify side, and
// hash_crack gains a phpass dictionary mode.
//
// # Wrap-vs-native judgement
//
// Native. phpass is an iterated MD5 (h = MD5(salt|pw); then h = MD5(h|pw) for
// 2^N rounds) finished with phpass's own base64 — a few dozen lines over
// crypto/md5; there is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The round count encoding, the MD5 loop, and the phpass base64 were confirmed
// against the reference passlib library (an independent oracle). Verify
// constant-time-compares the recomputed setting string, so a wrong password is
// reported as such, never asserted to match. A hash whose embedded cost is
// absurd (> 2^24 rounds) is rejected rather than allowed to hang.
//
// # Covered / deferred
//
// Covered: phpass $P$ (WordPress) and $H$ (phpBB3), verify + compute. The older
// non-portable WordPress MD5 and the bcrypt-backed $wp$ hashes are out of scope
// (the latter is the bcrypt tool's domain).
package phpass

import (
	"crypto/md5" //nolint:gosec // phpass is MD5-based by definition; the algorithm is the format, not a security choice.
	"crypto/subtle"
	"fmt"
	"strings"
)

const itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// maxRoundsLog caps the iteration exponent: 2^24 MD5 rounds is already far above
// any real WordPress/phpBB hash (~2^13), so a larger embedded cost is a hostile
// hash and is rejected rather than allowed to hang.
const maxRoundsLog = 24

// encode64 is phpass's own base64 (distinct from crypt's bit order).
func encode64(input []byte) string {
	var out strings.Builder
	n := len(input)
	i := 0
	for i < n {
		value := int(input[i])
		i++
		out.WriteByte(itoa64[value&0x3f])
		if i < n {
			value |= int(input[i]) << 8
		}
		out.WriteByte(itoa64[(value>>6)&0x3f])
		if i >= n {
			break
		}
		i++
		if i < n {
			value |= int(input[i]) << 16
		}
		out.WriteByte(itoa64[(value>>12)&0x3f])
		if i >= n {
			break
		}
		i++
		out.WriteByte(itoa64[(value>>18)&0x3f])
	}
	return out.String()
}

// crypt computes the full phpass hash string for password under the given
// setting (the first 12 chars: magic + round char + 8-byte salt).
func crypt(password, setting string) (string, error) {
	if len(setting) < 12 {
		return "", fmt.Errorf("phpass: setting too short (need magic + round + 8-byte salt)")
	}
	magic := setting[:3]
	if magic != "$P$" && magic != "$H$" {
		return "", fmt.Errorf("phpass: unrecognised magic %q (expected $P$ or $H$)", magic)
	}
	roundLog := strings.IndexByte(itoa64, setting[3])
	if roundLog < 0 {
		return "", fmt.Errorf("phpass: invalid round character %q", string(setting[3]))
	}
	if roundLog > maxRoundsLog {
		return "", fmt.Errorf("phpass: round cost 2^%d exceeds the 2^%d cap (hostile hash)", roundLog, maxRoundsLog)
	}
	count := 1 << uint(roundLog)
	salt := setting[4:12]

	pw := []byte(password)
	sum := md5.Sum(append([]byte(salt), pw...))
	hb := sum[:]
	buf := make([]byte, 0, len(hb)+len(pw))
	for i := 0; i < count; i++ {
		buf = append(buf[:0], hb...)
		buf = append(buf, pw...)
		s := md5.Sum(buf)
		hb = s[:]
	}
	return magic + string(setting[3]) + salt + encode64(hb), nil
}

// Verify reports whether password produces the given phpass ($P$ / $H$) hash.
func Verify(stored, password string) (bool, error) {
	got, err := crypt(password, stored)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(stored)) == 1, nil
}

// Compute builds a phpass hash for password. magic is "$P$" (WordPress) or "$H$"
// (phpBB3); roundsLog is the iteration exponent (2^roundsLog rounds; WordPress
// uses ~13); salt must be 8 characters.
func Compute(magic string, roundsLog int, salt, password string) (string, error) {
	if magic != "$P$" && magic != "$H$" {
		return "", fmt.Errorf("phpass: magic must be \"$P$\" or \"$H$\"")
	}
	if roundsLog < 7 || roundsLog > maxRoundsLog {
		return "", fmt.Errorf("phpass: roundsLog must be 7-%d", maxRoundsLog)
	}
	if len(salt) != 8 {
		return "", fmt.Errorf("phpass: salt must be 8 characters (got %d)", len(salt))
	}
	setting := magic + string(itoa64[roundsLog]) + salt
	return crypt(password, setting)
}
