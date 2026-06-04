// SPDX-License-Identifier: AGPL-3.0-or-later

package ciscopw

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/wpa"
)

// Cisco IOS "type 8" passwords (the `secret` / `enable secret` algorithm
// introduced August 2013, hashcat mode 9200) are PBKDF2-HMAC-SHA256 with an
// 80-bit salt and 20 000 iterations, encoded in the Cisco base64 alphabet:
//
//	$8$<salt>$<digest>
//
// where <salt> is 14 Cisco-base64 characters and <digest> is the 43-character
// Cisco-base64 of the 32-byte PBKDF2 output. The salt fed to PBKDF2 is the
// ASCII bytes of the <salt> string itself (not its decoded value) — a Cisco
// quirk confirmed against the published vectors below.
//
// Verifiable / no confidently-wrong output: the construction is pinned to the
// canonical hashcat mode-9200 example `$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.
// EMHr6M.FzU8xnZnBr/tJdFWk` (password "hashcat") and a second cracked vector
// `$8$dsYGNam3K1SIJO$7nv/35M/qr6t.dVc7UY9zrJDWRVqncHub1PE9UlMQFs` (password
// "cisco"); both are reproduced byte-for-byte in the unit tests.
//
// Type 9 (scrypt) is deliberately not implemented here: scrypt is not in the
// standard library and a wrong scrypt parameterisation would be
// confidently-wrong; hash_identify flags $9$ for cracking instead.

const (
	type8Iterations = 20000
	type8KeyLen     = 32
	type8SaltChars  = 14
	// cisco64 is the Cisco base64 alphabet (same set as crypt(3), but the
	// 24-bit groups are packed big-endian — verified against the vectors).
	cisco64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

// cisco64Encode renders data in the Cisco base64 alphabet, packing each group
// of up to 3 bytes as a big-endian 24-bit value emitted most-significant
// 6 bits first. A 32-byte digest yields 43 characters.
func cisco64Encode(data []byte) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 3 {
		chunk := data[i:min(i+3, len(data))]
		var v uint32
		for _, c := range chunk {
			v = v<<8 | uint32(c)
		}
		v <<= uint(8 * (3 - len(chunk)))
		// chars emitted: 2 for 1 byte, 3 for 2 bytes, 4 for 3 bytes.
		for k := 3; k >= 4-(len(chunk)+1); k-- {
			b.WriteByte(cisco64[(v>>(6*uint(k)))&0x3f])
		}
	}
	return b.String()
}

// Type8Compute returns the Cisco type-8 hash of password. If salt is empty a
// random 14-character Cisco-base64 salt is generated; a supplied salt is used
// verbatim and must be 14 Cisco-base64 characters.
func Type8Compute(password, salt string) (string, error) {
	if salt == "" {
		s, err := randomCisco64(type8SaltChars)
		if err != nil {
			return "", err
		}
		salt = s
	}
	if err := validType8Salt(salt); err != nil {
		return "", err
	}
	dk := wpa.PBKDF2([]byte(password), []byte(salt), type8Iterations, type8KeyLen, sha256.New)
	return "$8$" + salt + "$" + cisco64Encode(dk), nil
}

// Type8Verify reports whether password produces the given $8$ hash
// (constant-time). A malformed hash returns an error rather than false.
func Type8Verify(password, hash string) (bool, error) {
	salt, digest, err := parseType8(hash)
	if err != nil {
		return false, err
	}
	dk := wpa.PBKDF2([]byte(password), []byte(salt), type8Iterations, type8KeyLen, sha256.New)
	want := cisco64Encode(dk)
	return subtle.ConstantTimeCompare([]byte(want), []byte(digest)) == 1, nil
}

// parseType8 splits a "$8$<salt>$<digest>" string into its fields, validating
// the prefix, the salt length/alphabet, and the digest length/alphabet.
func parseType8(hash string) (salt, digest string, err error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(hash), "$8$")
	if !ok {
		return "", "", fmt.Errorf("not a Cisco type-8 hash (missing $8$ prefix)")
	}
	salt, digest, ok = strings.Cut(rest, "$")
	if !ok {
		return "", "", fmt.Errorf("malformed type-8 hash: missing '$' between salt and digest")
	}
	if err := validType8Salt(salt); err != nil {
		return "", "", err
	}
	if len(digest) != 43 {
		return "", "", fmt.Errorf("malformed type-8 hash: digest must be 43 chars, got %d", len(digest))
	}
	if !allCisco64(digest) {
		return "", "", fmt.Errorf("malformed type-8 hash: digest has non-Cisco-base64 characters")
	}
	return salt, digest, nil
}

func validType8Salt(salt string) error {
	if len(salt) != type8SaltChars {
		return fmt.Errorf("type-8 salt must be %d chars, got %d", type8SaltChars, len(salt))
	}
	if !allCisco64(salt) {
		return fmt.Errorf("type-8 salt has non-Cisco-base64 characters")
	}
	return nil
}

func allCisco64(s string) bool {
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(cisco64, s[i]) < 0 {
			return false
		}
	}
	return true
}

// randomCisco64 returns n characters drawn uniformly from the Cisco base64
// alphabet (used to mint a fresh salt).
func randomCisco64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = cisco64[int(buf[i])%len(cisco64)]
	}
	return string(buf), nil
}
