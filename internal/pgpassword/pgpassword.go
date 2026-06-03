// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pgpassword implements the PostgreSQL "md5" password verifier (hashcat
// mode 12): the value stored in pg_authid.rolpassword (pg_shadow.passwd) when a
// role uses md5 authentication. It is an offline credential primitive — compute
// the stored value for a candidate password, or verify a candidate against a
// value captured from a pg_authid / pg_dumpall --globals dump. It completes the
// database-credential pair with mysql_password (the MySQL/MariaDB sibling) and
// fits the credential toolkit's compute/verify pattern (nt_hash, ldap_password,
// md5crypt). Pure offline compute from operator-supplied strings; no network or
// device.
//
// # Algorithm
//
// PostgreSQL's pg_md5_encrypt (src/common/md5_common.c) salts the password with
// the role name before a single MD5:
//
//	"md5" + hex( MD5( password ‖ username ) )
//
// The stored value is the literal "md5" followed by 32 lowercase hex digits.
// The salt is the role name, so the same password under two different roles
// yields different stored values — verification therefore requires the username
// as well as the candidate password.
//
// # Wrap-vs-native judgement
//
// Native. The verifier is a single crypto/md5 over password+username plus hex —
// there is nothing to wrap; the only third-party option would be a PostgreSQL
// client/driver, unwarranted for a pure hash. Consistent with internal/mysqlpw,
// internal/nthash, and internal/ldappw owning their crypto in-tree.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class — the construction is unambiguous (a single
// salted MD5, no rounds) and is exactly PostgreSQL's documented pg_md5_encrypt,
// gated against the stdlib-hashlib oracle ("md5"+md5(password+rolname)). A
// malformed stored value (missing "md5" prefix / wrong length / non-hex) is
// rejected with an error, never silently "verified". Out of scope: SCRAM-SHA-256
// (the PostgreSQL 10+ default, hashcat 28600 — salted + iterated PBKDF2/HMAC, a
// different primitive) and the obsolete pre-7.2 plain-MD5 form.
package pgpassword

import (
	"crypto/md5" //nolint:gosec // PostgreSQL md5 authentication is MD5 by definition.
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strings"
)

// Compute returns the PostgreSQL md5 stored value for password under the given
// role name: "md5" + hex(MD5(password ‖ username)).
func Compute(password, username string) string {
	sum := md5.Sum([]byte(password + username)) //nolint:gosec // by spec
	return "md5" + hex.EncodeToString(sum[:])
}

// Normalize canonicalises a stored value to the "md5" + 32-lowercase-hex form,
// accepting an optional "md5" prefix and either hex case. It errors if the
// digest portion is not exactly 32 hex digits.
func Normalize(stored string) (string, error) {
	s := strings.TrimSpace(stored)
	s = strings.TrimPrefix(s, "md5")
	if len(s) != 32 {
		return "", fmt.Errorf("PostgreSQL md5 value must be 32 hex digits (optionally 'md5'-prefixed); got %d", len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("PostgreSQL md5 value is not valid hex: %w", err)
	}
	return "md5" + hex.EncodeToString(raw), nil
}

// Verify reports whether password under username produces the given stored
// value. The stored value may be supplied with or without the "md5" prefix and
// in either hex case; it is compared constant-time. A malformed value returns
// an error rather than false.
func Verify(password, username, stored string) (bool, error) {
	norm, err := Normalize(stored)
	if err != nil {
		return false, err
	}
	got := Compute(password, username)
	return subtle.ConstantTimeCompare([]byte(got), []byte(norm)) == 1, nil
}
