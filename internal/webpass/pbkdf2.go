// SPDX-License-Identifier: AGPL-3.0-or-later

// Package webpass verifies and computes the PBKDF2 password hashes used by the
// two dominant Python web frameworks: Django (pbkdf2_sha256$…) and Werkzeug /
// Flask (pbkdf2:sha256:…). These are the format of the user-credential rows in
// a Django/Flask database dump — a very common offline-crack target — that the
// credential toolkit could not previously verify, compute or crack.
//
// # Wrap-vs-native judgement
//
// Native. Both are PBKDF2-HMAC over the standard library's crypto/sha*, reusing
// the generic PBKDF2 already in internal/wpa; only the framework-specific string
// framing (separators, salt-as-string, base64 vs hex digest) is added here.
//
// # Verifiable / no confidently-wrong output
//
// The exact framing — PBKDF2-HMAC-SHA256, the salt used as raw bytes, a 32-byte
// derived key, Django's padded standard base64 vs Werkzeug's hex — was confirmed
// against the reference Django and Werkzeug libraries (an independent oracle) and
// against raw hashlib.pbkdf2_hmac. Verify constant-time-compares the recomputed
// derived key to the stored one, so a wrong password is reported as such, never
// asserted to match.
//
// # Covered / deferred
//
// Covered: Django pbkdf2_sha256 / pbkdf2_sha1, Werkzeug pbkdf2:{sha256,sha1,
// sha512}, and Werkzeug scrypt:N:r:p (the modern Flask default — see scrypt.go),
// verify + compute. Deferred: Django's bcrypt/argon2 hasher wrappers (those
// delegate to the bcrypt/argon2 tools).
package webpass

import (
	"crypto/sha1" //nolint:gosec // pbkdf2_sha1 is a supported framework variant; the algorithm is selected by the hash, not a security choice.
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/xunholy/promptzero/internal/wpa"
)

func hashFor(algo string) (func() hash.Hash, int, error) {
	switch algo {
	case "sha256":
		return sha256.New, 32, nil
	case "sha1":
		return sha1.New, 20, nil
	case "sha512":
		return sha512.New, 64, nil
	default:
		return nil, 0, fmt.Errorf("webpass: unsupported PBKDF2 hash %q (sha256/sha1/sha512)", algo)
	}
}

// Scheme reports the framework a hash belongs to ("django" / "werkzeug" / "").
func Scheme(stored string) string {
	switch {
	case strings.HasPrefix(stored, "pbkdf2_"):
		return "django"
	case strings.HasPrefix(stored, "pbkdf2:"), strings.HasPrefix(stored, "scrypt:"):
		return "werkzeug"
	default:
		return ""
	}
}

// Verify reports whether password produces the given Django/Werkzeug PBKDF2 or
// Werkzeug scrypt hash. The format is auto-detected from the prefix.
func Verify(stored, password string) (bool, error) {
	if strings.HasPrefix(stored, "scrypt:") {
		return verifyScrypt(stored, password)
	}
	algo, iter, salt, digest, err := parse(stored)
	if err != nil {
		return false, err
	}
	h, _, err := hashFor(algo)
	if err != nil {
		return false, err
	}
	got := wpa.PBKDF2([]byte(password), []byte(salt), iter, len(digest), h)
	return subtle.ConstantTimeCompare(got, digest) == 1, nil
}

// parse extracts (algo, iterations, salt, digest-bytes) from a Django or
// Werkzeug PBKDF2 hash.
func parse(stored string) (algo string, iter int, salt string, digest []byte, err error) {
	switch Scheme(stored) {
	case "django":
		// pbkdf2_<algo>$<iter>$<salt>$<base64-std digest>
		p := strings.Split(stored, "$")
		if len(p) != 4 {
			return "", 0, "", nil, fmt.Errorf("webpass: malformed Django hash (want algo$iter$salt$hash)")
		}
		algo = strings.TrimPrefix(p[0], "pbkdf2_")
		if iter, err = parseIter(p[1]); err != nil {
			return "", 0, "", nil, err
		}
		salt = p[2]
		if digest, err = base64.StdEncoding.DecodeString(p[3]); err != nil {
			return "", 0, "", nil, fmt.Errorf("webpass: Django digest not base64: %w", err)
		}
	case "werkzeug":
		// pbkdf2:<algo>:<iter>$<salt>$<hex digest>
		i := strings.IndexByte(stored, '$')
		if i < 0 {
			return "", 0, "", nil, fmt.Errorf("webpass: malformed Werkzeug hash (no '$')")
		}
		method := strings.Split(stored[:i], ":")
		if len(method) != 3 {
			return "", 0, "", nil, fmt.Errorf("webpass: malformed Werkzeug method (want pbkdf2:algo:iter)")
		}
		algo = method[1]
		if iter, err = parseIter(method[2]); err != nil {
			return "", 0, "", nil, err
		}
		rest := strings.SplitN(stored[i+1:], "$", 2)
		if len(rest) != 2 {
			return "", 0, "", nil, fmt.Errorf("webpass: malformed Werkzeug hash (want method$salt$hash)")
		}
		salt = rest[0]
		if digest, err = hex.DecodeString(rest[1]); err != nil {
			return "", 0, "", nil, fmt.Errorf("webpass: Werkzeug digest not hex: %w", err)
		}
	default:
		return "", 0, "", nil, fmt.Errorf("webpass: not a Django/Werkzeug PBKDF2 hash")
	}
	if len(digest) == 0 {
		return "", 0, "", nil, fmt.Errorf("webpass: empty digest")
	}
	return algo, iter, salt, digest, nil
}

func parseIter(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("webpass: invalid iteration count %q", s)
	}
	return n, nil
}

// Compute builds a Django or Werkzeug PBKDF2 hash string for password.
func Compute(scheme, algo string, iter int, salt, password string) (string, error) {
	h, dklen, err := hashFor(algo)
	if err != nil {
		return "", err
	}
	if iter < 1 {
		return "", fmt.Errorf("webpass: iterations must be >= 1")
	}
	dk := wpa.PBKDF2([]byte(password), []byte(salt), iter, dklen, h)
	switch scheme {
	case "django":
		return fmt.Sprintf("pbkdf2_%s$%d$%s$%s", algo, iter, salt, base64.StdEncoding.EncodeToString(dk)), nil
	case "werkzeug":
		return fmt.Sprintf("pbkdf2:%s:%d$%s$%s", algo, iter, salt, hex.EncodeToString(dk)), nil
	default:
		return "", fmt.Errorf("webpass: scheme %q must be \"django\" or \"werkzeug\"", scheme)
	}
}
