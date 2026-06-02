// SPDX-License-Identifier: AGPL-3.0-or-later

// Package hmacutil computes and verifies HMAC-SHA1/SHA256/SHA512 message
// authentication codes. It is the keyed-MAC tier of the toolkit — the
// API/webhook-auth analogue of jwt_verify: verify or forge a webhook signature
// (GitHub X-Hub-Signature-256, Stripe-Signature, generic API request signing)
// with a known or leaked secret, or check a protocol's HMAC auth tag. It
// complements the unkeyed checksum tools (crc_compute / checksum_compute).
//
// # Wrap-vs-native judgement
//
// Native. HMAC is crypto/hmac over crypto/sha*; this is a thin, deterministic
// wrapper plus a named-algorithm table and a constant-time verify. Nothing to
// wrap.
//
// # Verifiable / no confidently-wrong output
//
// The strongest verification class: RFC 4231 publishes exact HMAC test
// vectors, and the unit tests assert this package reproduces them (e.g.
// HMAC-SHA256 with key "Jefe" over "what do ya want for nothing?" =
// 5bdcc146…ec3843). Verify uses a constant-time comparison.
//
// # Covered / deferred
//
// Covered: HMAC-SHA1 / SHA256 / SHA512, compute and verify. HMAC-MD5 (legacy,
// omitted on purpose), keyed BLAKE2, and the full AWS SigV4 multi-step signing
// flow are out of scope.
package hmacutil

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is still widely used for webhook/API signatures; offered for compatibility, not as a security recommendation.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"strings"
)

// HashFor maps an algorithm name to its hash constructor.
func HashFor(algo string) (func() hash.Hash, error) {
	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "", "SHA256", "SHA-256":
		return sha256.New, nil
	case "SHA1", "SHA-1":
		return sha1.New, nil
	case "SHA512", "SHA-512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("hmacutil: unsupported algorithm %q (SHA1 / SHA256 / SHA512)", algo)
	}
}

// Compute returns the HMAC of data under key for the given algorithm.
func Compute(algo string, key, data []byte) ([]byte, error) {
	h, err := HashFor(algo)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(h, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// Verify reports whether expected (a hex MAC) matches the HMAC of data under
// key, using a constant-time comparison.
func Verify(algo string, key, data []byte, expectedHex string) (bool, error) {
	want, err := hex.DecodeString(strings.TrimSpace(strings.TrimPrefix(expectedHex, "0x")))
	if err != nil {
		return false, fmt.Errorf("hmacutil: expected MAC is not valid hex: %w", err)
	}
	got, err := Compute(algo, key, data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(got, want), nil
}
