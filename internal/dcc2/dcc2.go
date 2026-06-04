// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dcc2 implements Domain Cached Credentials v2 (DCC2 / MS-Cache v2 /
// mscash2, hashcat mode 2100): the format Windows (Vista / Server 2008+) uses
// to cache domain logons locally, dumped from a compromised workstation's
// SECURITY registry hive (HKLM\SECURITY\Cache, e.g. via impacket secretsdump).
// Unlike an NT hash a DCC2 cannot be passed-the-hash — it is an offline-crack-
// only credential — so the compute/verify side completes the credential
// toolkit: hash_identify recognises $DCC2$ (mode 2100) and hash_crack attacks
// it, but neither could produce or check one. Pure offline compute from
// operator-supplied strings; no network or device.
//
// # Algorithm
//
//	DCC1 = MD4( MD4(password‖UTF-16LE) ‖ lower(username)‖UTF-16LE )   (= MS-Cache v1)
//	DCC2 = PBKDF2-HMAC-SHA1( DCC1, lower(username)‖UTF-16LE, iterations, 16 )
//
// The username (lowercased, UTF-16LE) is the PBKDF2 salt; the default iteration
// count is 10240. The stored form is `$DCC2$<iterations>#<username>#<hex>`.
//
// # Wrap-vs-native judgement
//
// Native. It composes two in-tree primitives — internal/nthash.MD4 (the
// RFC-1320-verified MD4 behind nt_hash) and internal/wpa.PBKDF2 (the generic
// PBKDF2 behind pbkdf2_password / wpa_pmk_derive / postgres_scram) — plus
// UTF-16LE encoding. There is nothing to wrap; consistent with the other in-tree
// credential computes owning their crypto.
//
// # Verifiable / no confidently-wrong output
//
// Strongest verification class — gated byte-for-byte against the canonical
// hashcat mode-2100 example $DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f
// (password "hashcat"), the independent anchor, plus pycryptodome-confirmed
// vectors. A malformed hash (wrong prefix / field count / iteration count /
// non-hex) is rejected with an error, never silently "verified".
package dcc2

import (
	"crypto/sha1" //nolint:gosec // mscash2 (DCC2) is PBKDF2-HMAC-SHA1 by definition.
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"

	"github.com/xunholy/promptzero/internal/nthash"
	"github.com/xunholy/promptzero/internal/wpa"
)

const (
	defaultIterations = 10240
	maxIterations     = 1 << 24 // sanity cap so a hostile hash can't wedge PBKDF2
	dkLen             = 16
)

// utf16le encodes a string as little-endian UTF-16 (the Windows password /
// username encoding).
func utf16le(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2*len(u))
	for i, r := range u {
		binary.LittleEndian.PutUint16(b[2*i:], r)
	}
	return b
}

// dcc1 computes MS-Cache v1: MD4( MD4(password) ‖ lower(username) ), all
// UTF-16LE.
func dcc1(username, password string) []byte {
	nt := nthash.MD4(utf16le(password))
	buf := make([]byte, 0, len(nt)+len(username)*2)
	buf = append(buf, nt...)
	buf = append(buf, utf16le(strings.ToLower(username))...)
	return nthash.MD4(buf)
}

// Compute returns the DCC2 stored value for (username, password). iterations
// <= 0 selects the default of 10240.
func Compute(username, password string, iterations int) (string, error) {
	if iterations <= 0 {
		iterations = defaultIterations
	}
	if iterations > maxIterations {
		return "", fmt.Errorf("dcc2: iterations %d exceeds sane maximum %d", iterations, maxIterations)
	}
	salt := utf16le(strings.ToLower(username))
	dk := wpa.PBKDF2(dcc1(username, password), salt, iterations, dkLen, sha1.New)
	return fmt.Sprintf("$DCC2$%d#%s#%s", iterations, username, hex.EncodeToString(dk)), nil
}

// Parsed is a decomposed DCC2 hash.
type Parsed struct {
	Iterations int
	Username   string
	Hash       string // 32 lowercase hex chars
}

// Parse decomposes a `$DCC2$<iterations>#<username>#<hex>` string.
func Parse(s string) (*Parsed, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "$DCC2$")
	if !ok {
		return nil, fmt.Errorf("dcc2: not a $DCC2$ hash")
	}
	parts := strings.SplitN(rest, "#", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("dcc2: expected $DCC2$<iterations>#<username>#<hash>")
	}
	iter, err := strconv.Atoi(parts[0])
	if err != nil || iter <= 0 {
		return nil, fmt.Errorf("dcc2: bad iteration count %q", parts[0])
	}
	if iter > maxIterations {
		return nil, fmt.Errorf("dcc2: iteration count %d exceeds sane maximum %d", iter, maxIterations)
	}
	h := strings.ToLower(parts[2])
	if len(h) != 32 {
		return nil, fmt.Errorf("dcc2: hash must be 32 hex chars, got %d", len(h))
	}
	if _, err := hex.DecodeString(h); err != nil {
		return nil, fmt.Errorf("dcc2: hash is not valid hex: %w", err)
	}
	return &Parsed{Iterations: iter, Username: parts[1], Hash: h}, nil
}

// Result is the outcome of verifying a candidate password.
type Result struct {
	Matched    bool   `json:"matched"`
	Username   string `json:"username"`
	Iterations int    `json:"iterations"`
}

// Verify reports whether password produces the given $DCC2$ hash (the username
// and iteration count are taken from the hash). Compared constant-time.
func Verify(password, hash string) (*Result, error) {
	p, err := Parse(hash)
	if err != nil {
		return nil, err
	}
	got, err := Compute(p.Username, password, p.Iterations)
	if err != nil {
		return nil, err
	}
	want := "$DCC2$" + strconv.Itoa(p.Iterations) + "#" + p.Username + "#" + p.Hash
	return &Result{
		Matched:    subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1,
		Username:   p.Username,
		Iterations: p.Iterations,
	}, nil
}
