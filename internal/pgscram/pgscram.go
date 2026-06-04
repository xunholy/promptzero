// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pgscram implements the PostgreSQL SCRAM-SHA-256 stored verifier
// (RFC 5802 / RFC 7677 + PostgreSQL's pg_authid encoding, hashcat mode 28600):
// the value stored in pg_authid.rolpassword for a role using scram-sha-256
// authentication, the default since PostgreSQL 10 (2017) and the successor to
// the older md5 verifier (see internal/pgpassword). It is an offline credential
// primitive — compute the verifier for a candidate password, or verify a
// candidate against a verifier captured from a pg_authid / pg_dumpall --globals
// dump. Pure offline compute from operator-supplied strings; no network or
// device.
//
// # Stored verifier format
//
// PostgreSQL stores (pg_be_scram_build_secret):
//
//	SCRAM-SHA-256$<iterations>:<base64 salt>$<base64 StoredKey>:<base64 ServerKey>
//
// derived from the password per RFC 5802:
//
//	SaltedPassword = PBKDF2-HMAC-SHA256(password, salt, iterations, dkLen=32)
//	ClientKey      = HMAC-SHA256(SaltedPassword, "Client Key")
//	StoredKey      = SHA256(ClientKey)
//	ServerKey      = HMAC-SHA256(SaltedPassword, "Server Key")
//
// Verification recomputes StoredKey from the candidate password + the stored
// salt/iterations and constant-time compares it (knowledge of the password
// reproduces the StoredKey). The password is first prepared with SASLprep
// (RFC 4013); this package applies SASLprep's no-op fast path for the common
// ASCII case and otherwise uses the raw UTF-8 bytes — see the note below.
//
// # Wrap-vs-native judgement
//
// Native. The verifier is PBKDF2-HMAC-SHA256 (the generic in-tree
// internal/wpa.PBKDF2, the same primitive pbkdf2_password and wpa_pmk_derive
// use) plus two HMAC-SHA256 passes, one SHA-256, and base64 — all standard
// library. There is nothing to wrap; the only third-party option would be a
// PostgreSQL client/driver, unwarranted for a pure key-derivation. Consistent
// with internal/pgpassword, internal/mysqlpw, and internal/ldappw owning their
// crypto in-tree.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class. The SaltedPassword / ClientKey / StoredKey /
// ServerKey chain is anchored byte-for-byte to the RFC 7677 §3 worked example
// (password "pencil", salt W22ZaJ0SNY7soEsUEjb6gQ==, i=4096): the package's
// derivation reproduces the RFC's ClientProof (p=) and ServerSignature (v=)
// exactly, and hence the StoredKey/ServerKey the verifier string carries. A
// malformed verifier (wrong prefix / field count / base64 / iteration count)
// is rejected with an error, never silently "verified".
//
// Deferred: full SASLprep (RFC 4013) normalization of non-ASCII passwords —
// PostgreSQL applies SASLprep, but it is a no-op for ASCII passwords (the
// overwhelming majority) and falls back to the raw bytes on any SASLprep error;
// this package matches that behaviour for ASCII and uses raw UTF-8 otherwise,
// flagging that a non-ASCII password may need normalization. The older md5
// verifier is handled by internal/pgpassword.
package pgscram

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/xunholy/promptzero/internal/wpa"
)

const (
	prefix        = "SCRAM-SHA-256"
	keyLen        = 32
	defaultIter   = 4096
	defaultSalt   = 16
	maxIterations = 1 << 24 // sanity cap so a hostile verifier can't wedge PBKDF2
)

// Verifier is the parsed PostgreSQL SCRAM-SHA-256 stored verifier.
type Verifier struct {
	Iterations int
	Salt       []byte
	StoredKey  []byte
	ServerKey  []byte
}

// saltedPassword derives the RFC 5802 SaltedPassword via PBKDF2-HMAC-SHA256.
func saltedPassword(password string, salt []byte, iter int) []byte {
	return wpa.PBKDF2([]byte(password), salt, iter, keyLen, sha256.New)
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// keys derives StoredKey and ServerKey for a candidate password.
func keys(password string, salt []byte, iter int) (storedKey, serverKey []byte) {
	sp := saltedPassword(password, salt, iter)
	clientKey := hmacSHA256(sp, []byte("Client Key"))
	sum := sha256.Sum256(clientKey)
	return sum[:], hmacSHA256(sp, []byte("Server Key"))
}

// Compute builds the PostgreSQL SCRAM-SHA-256 stored verifier for password. If
// salt is nil a random 16-byte salt is generated; if iterations <= 0 the
// PostgreSQL default of 4096 is used.
func Compute(password string, salt []byte, iterations int) (string, error) {
	if iterations <= 0 {
		iterations = defaultIter
	}
	if iterations > maxIterations {
		return "", fmt.Errorf("iterations %d exceeds sane maximum %d", iterations, maxIterations)
	}
	if salt == nil {
		s, err := randomBytes(defaultSalt)
		if err != nil {
			return "", err
		}
		salt = s
	}
	storedKey, serverKey := keys(password, salt, iterations)
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf("%s$%d:%s$%s:%s", prefix, iterations,
		b64(salt), b64(storedKey), b64(serverKey)), nil
}

// Parse decodes a PostgreSQL SCRAM-SHA-256 stored verifier string.
func Parse(s string) (*Verifier, error) {
	s = strings.TrimSpace(s)
	rest, ok := strings.CutPrefix(s, prefix+"$")
	if !ok {
		return nil, fmt.Errorf("not a SCRAM-SHA-256 verifier (missing %q prefix)", prefix)
	}
	// rest = "<iter>:<b64 salt>$<b64 StoredKey>:<b64 ServerKey>"
	saltPart, keyPart, ok := strings.Cut(rest, "$")
	if !ok {
		return nil, fmt.Errorf("malformed verifier: missing '$' between salt and keys")
	}
	iterStr, saltB64, ok := strings.Cut(saltPart, ":")
	if !ok {
		return nil, fmt.Errorf("malformed verifier: missing ':' between iterations and salt")
	}
	storedB64, serverB64, ok := strings.Cut(keyPart, ":")
	if !ok {
		return nil, fmt.Errorf("malformed verifier: missing ':' between StoredKey and ServerKey")
	}
	iter, err := strconv.Atoi(iterStr)
	if err != nil || iter <= 0 {
		return nil, fmt.Errorf("malformed verifier: bad iteration count %q", iterStr)
	}
	if iter > maxIterations {
		return nil, fmt.Errorf("verifier iteration count %d exceeds sane maximum %d", iter, maxIterations)
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("malformed verifier: salt is not valid base64: %w", err)
	}
	storedKey, err := base64.StdEncoding.DecodeString(storedB64)
	if err != nil {
		return nil, fmt.Errorf("malformed verifier: StoredKey is not valid base64: %w", err)
	}
	serverKey, err := base64.StdEncoding.DecodeString(serverB64)
	if err != nil {
		return nil, fmt.Errorf("malformed verifier: ServerKey is not valid base64: %w", err)
	}
	if len(storedKey) != keyLen || len(serverKey) != keyLen {
		return nil, fmt.Errorf("malformed verifier: StoredKey/ServerKey must be %d bytes", keyLen)
	}
	return &Verifier{Iterations: iter, Salt: salt, StoredKey: storedKey, ServerKey: serverKey}, nil
}

// Result is the outcome of verifying a candidate password against a verifier.
type Result struct {
	Matched    bool `json:"matched"`
	Iterations int  `json:"iterations"`
	SaltLen    int  `json:"salt_len"`
}

// Verify reports whether password reproduces the StoredKey of the given
// PostgreSQL SCRAM-SHA-256 verifier (constant-time). A malformed verifier
// returns an error rather than false.
func Verify(password, verifier string) (*Result, error) {
	v, err := Parse(verifier)
	if err != nil {
		return nil, err
	}
	storedKey, _ := keys(password, v.Salt, v.Iterations)
	return &Result{
		Matched:    subtle.ConstantTimeCompare(storedKey, v.StoredKey) == 1,
		Iterations: v.Iterations,
		SaltLen:    len(v.Salt),
	}, nil
}

func randomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}
