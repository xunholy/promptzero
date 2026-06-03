// SPDX-License-Identifier: AGPL-3.0-or-later

package webpass

import (
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// scryptMaxMem caps scrypt's working set (128 * N * r bytes) at 1 GiB — far
// above Werkzeug's default (N=32768, r=8 → 32 MiB), so a hostile hash with an
// absurd N/r is rejected rather than allowed to exhaust memory.
//
// Wrap-vs-native: wrap — scrypt (Salsa20/8 + BlockMix + ROMix) is implemented by
// golang.org/x/crypto/scrypt, already a project dependency; a faithful native
// port is large and would be less trustworthy. Only the Werkzeug string framing
// (scrypt:N:r:p$salt$hex) is our own code, gated against the reference Werkzeug
// library + Go's x/crypto/scrypt.
const scryptMaxMem = 1 << 30

// verifyScrypt verifies a Werkzeug scrypt hash: scrypt:N:r:p$salt$hexdigest.
func verifyScrypt(stored, password string) (bool, error) {
	i := strings.IndexByte(stored, '$')
	if i < 0 {
		return false, fmt.Errorf("webpass: malformed scrypt hash (no '$')")
	}
	method := strings.Split(stored[:i], ":")
	if len(method) != 4 {
		return false, fmt.Errorf("webpass: malformed scrypt method (want scrypt:N:r:p)")
	}
	n, err1 := strconv.Atoi(method[1])
	r, err2 := strconv.Atoi(method[2])
	p, err3 := strconv.Atoi(method[3])
	if err1 != nil || err2 != nil || err3 != nil || n < 2 || r < 1 || p < 1 {
		return false, fmt.Errorf("webpass: invalid scrypt N/r/p")
	}
	if int64(128)*int64(n)*int64(r) > scryptMaxMem {
		return false, fmt.Errorf("webpass: scrypt N=%d r=%d exceeds the memory cap (hostile hash)", n, r)
	}
	rest := strings.SplitN(stored[i+1:], "$", 2)
	if len(rest) != 2 {
		return false, fmt.Errorf("webpass: malformed scrypt hash (want method$salt$hash)")
	}
	salt := rest[0]
	digest, err := hex.DecodeString(rest[1])
	if err != nil {
		return false, fmt.Errorf("webpass: scrypt digest not hex: %w", err)
	}
	if len(digest) == 0 {
		return false, fmt.Errorf("webpass: empty scrypt digest")
	}
	got, err := scrypt.Key([]byte(password), []byte(salt), n, r, p, len(digest))
	if err != nil {
		return false, fmt.Errorf("webpass: scrypt: %w", err)
	}
	return subtle.ConstantTimeCompare(got, digest) == 1, nil
}

// ComputeScrypt builds a Werkzeug scrypt hash (scrypt:N:r:p$salt$hex).
func ComputeScrypt(n, r, p int, salt, password string) (string, error) {
	if n < 2 || r < 1 || p < 1 {
		return "", fmt.Errorf("webpass: invalid scrypt N/r/p")
	}
	if int64(128)*int64(n)*int64(r) > scryptMaxMem {
		return "", fmt.Errorf("webpass: scrypt N=%d r=%d exceeds the memory cap", n, r)
	}
	dk, err := scrypt.Key([]byte(password), []byte(salt), n, r, p, 64)
	if err != nil {
		return "", fmt.Errorf("webpass: scrypt: %w", err)
	}
	return fmt.Sprintf("scrypt:%d:%d:%d$%s$%s", n, r, p, salt, hex.EncodeToString(dk)), nil
}
