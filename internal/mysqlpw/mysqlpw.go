// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mysqlpw implements the MySQL / MariaDB mysql_native_password hash
// (the "4.1+" PASSWORD() format, hashcat mode 300): the value stored in
// mysql.user.authentication_string / Password. It is an offline credential
// primitive — compute the hash of a candidate password, or verify a candidate
// against a hash captured from a mysql.user dump. It complements the credential
// toolkit: hash_identify recognises this format ("MySQL4.1+", mode 300) and
// hash_crack_dictionary attacks it, but neither could produce or check one —
// the same compute/verify gap nt_hash and ldap_password fill for their formats.
// Pure offline compute from operator-supplied strings; no network or device.
//
// # Algorithm
//
// mysql_native_password is an unsalted double SHA-1:
//
//	"*" + UPPER( hex( SHA1( SHA1( password ) ) ) )
//
// The stored value is a 41-character string: a literal '*' followed by 40
// uppercase hex digits. (The handshake-time scramble salts this with the
// server's nonce, but the *stored* credential — the loot — is the unsalted
// double hash decoded here.) There is no per-row salt, so two accounts with the
// same password share a hash.
//
// # Wrap-vs-native judgement
//
// Native. The hash is two crypto/sha1 passes plus hex — there is nothing to
// wrap; the only third-party option would be a MySQL client/driver, unwarranted
// for a pure hash. The identical algorithm already backs the "mysql" branch of
// hash_crack_dictionary (internal/tools/security.go); this package factors the
// compute/verify side out so it is callable directly, consistent with
// internal/nthash, internal/unixcrypt, and internal/ldappw owning their crypto.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class — the construction is unambiguous (double SHA-1,
// no rounds, no salt) and gated against the universally-published MySQL vector
// PASSWORD('password') = *2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19, plus the
// hashcat-300 example. A malformed hash (wrong length / non-hex / missing '*')
// is rejected with an error, never silently "verified". Out of scope: the
// pre-4.1 OLD_PASSWORD 16-hex format (hashcat 200 — obsolete since 2003) and the
// caching_sha2_password / sha256_password plugins (salted, iterated — a
// different primitive).
package mysqlpw

import (
	"crypto/sha1" //nolint:gosec // mysql_native_password is SHA-1 by definition.
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// Compute returns the mysql_native_password hash of password: the 41-character
// "*" + UPPER(hex(SHA1(SHA1(password)))) form stored in mysql.user.
func Compute(password string) string {
	inner := sha1.Sum([]byte(password))
	outer := sha1.Sum(inner[:])
	return "*" + strings.ToUpper(hex.EncodeToString(outer[:]))
}

// Normalize canonicalises a stored hash to the "*" + 40-uppercase-hex form,
// accepting an optional leading '*' and either case. It errors if the value is
// not exactly 40 hex digits (with or without the '*').
func Normalize(hash string) (string, error) {
	h := strings.TrimSpace(hash)
	h = strings.TrimPrefix(h, "*")
	if len(h) != 40 {
		return "", fmt.Errorf("mysql_native_password hash must be 40 hex digits (optionally '*'-prefixed); got %d", len(h))
	}
	raw, err := hex.DecodeString(h)
	if err != nil {
		return "", fmt.Errorf("mysql_native_password hash is not valid hex: %w", err)
	}
	return "*" + strings.ToUpper(hex.EncodeToString(raw)), nil
}

// Verify reports whether password produces the given stored hash. The hash may
// be supplied with or without the leading '*' and in either hex case; it is
// compared constant-time. A malformed hash returns an error rather than false.
func Verify(password, hash string) (bool, error) {
	norm, err := Normalize(hash)
	if err != nil {
		return false, err
	}
	got := Compute(password)
	return subtle.ConstantTimeCompare([]byte(got), []byte(norm)) == 1, nil
}
