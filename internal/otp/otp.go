// SPDX-License-Identifier: AGPL-3.0-or-later

// Package otp computes RFC 4226 HOTP and RFC 6238 TOTP one-time passwords. It
// is an offline post-exploitation primitive: when a 2FA seed has been
// recovered from captured loot (a secrets file, a config dump, an otpauth://
// URI / QR payload), this derives the live codes — complementing the credential
// tooling (hash_identify, jwt_decode, kerberos_decode). It computes from an
// operator-supplied seed; it performs no network or device interaction.
//
// # Wrap-vs-native judgement
//
// Native. HOTP is HMAC + the RFC 4226 dynamic-truncation; TOTP is HOTP over a
// time-step counter. Both are a dozen lines on top of the standard library's
// crypto/hmac + crypto/sha*. There is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// This is the strongest verification class: RFC 4226 (Appendix D) and RFC 6238
// (Appendix B) publish exact test vectors — seed "12345678901234567890",
// HOTP counter 0 -> 755224, TOTP SHA-1 T=59 -> 94287082, etc. The unit tests
// assert this package reproduces every published vector, so the algorithm
// ships only if it matches the authoritative reference.
//
// # Covered / deferred
//
// Covered: HOTP, TOTP, the SHA-1 / SHA-256 / SHA-512 HMAC variants, 6-8 digit
// codes, base32 seed decoding (the Google-Authenticator form), and the
// otpauth:// key-URI parser (ParseURI — the 2FA-enrolment QR artifact, carrying
// the algorithm / digits / period that drive the code), and Steam Guard
// (SteamGuard — RFC 6238 over SHA1/30s mapped to Steam's 5-character alphabet,
// from a base64 shared_secret). Nothing in this package is deferred.
package otp

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // HOTP/TOTP are HMAC-SHA1 by RFC; this is the spec algorithm, not a security choice.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
	"time"
)

// HashFor maps an algorithm name to its hash constructor.
func HashFor(algo string) (func() hash.Hash, error) {
	switch strings.ToUpper(strings.TrimSpace(algo)) {
	case "", "SHA1", "SHA-1":
		return sha1.New, nil
	case "SHA256", "SHA-256":
		return sha256.New, nil
	case "SHA512", "SHA-512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("otp: unsupported algorithm %q (SHA1 / SHA256 / SHA512)", algo)
	}
}

// dynamicTruncate is the RFC 4226 dynamic-truncation step shared by HOTP and the
// Steam-Guard variant: HMAC the 8-byte big-endian counter, then extract the
// 31-bit value at the offset named by the low nibble of the last byte.
func dynamicTruncate(key []byte, counter uint64, h func() hash.Hash) uint32 {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(h, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0F
	return (uint32(sum[offset]&0x7F) << 24) |
		(uint32(sum[offset+1]) << 16) |
		(uint32(sum[offset+2]) << 8) |
		uint32(sum[offset+3])
}

// HOTP computes the RFC 4226 HOTP code for a key and counter.
func HOTP(key []byte, counter uint64, digits int, h func() hash.Hash) string {
	bin := dynamicTruncate(key, counter, h)
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// steamAlphabet is Steam Guard's 26-character code alphabet (vowels and visually
// confusable characters removed). The canonical order across every Steam-TOTP
// implementation; do not reorder.
const steamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"

// SteamGuard computes a Steam Guard mobile-authenticator code for time t. Steam
// uses RFC 6238 over an HMAC-SHA1 / 30-second step (T0 = 0) but, instead of the
// decimal modulo, maps the 31-bit truncated value to a fixed 5-character
// alphabet: take value mod 26 as an index five times, dividing by 26 each step.
// The seed is Steam's base64 shared_secret (decode with DecodeSecretBase64).
func SteamGuard(key []byte, t time.Time) string {
	bin := dynamicTruncate(key, uint64(t.Unix()/30), sha1.New)
	var b [5]byte
	for i := 0; i < 5; i++ {
		b[i] = steamAlphabet[bin%uint32(len(steamAlphabet))]
		bin /= uint32(len(steamAlphabet))
	}
	return string(b[:])
}

// TOTP computes the RFC 6238 TOTP code for time t (T0 = 0).
func TOTP(key []byte, t time.Time, period, digits int, h func() hash.Hash) string {
	counter := uint64(t.Unix() / int64(period))
	return HOTP(key, counter, digits, h)
}

// DecodeSecret decodes a base32 2FA secret, tolerating spaces, lowercase, and
// missing '=' padding (the common Google-Authenticator form).
func DecodeSecret(s string) ([]byte, error) {
	clean := strings.ToUpper(strings.NewReplacer(" ", "", "-", "", "\t", "", "\n", "").Replace(strings.TrimSpace(s)))
	if clean == "" {
		return nil, fmt.Errorf("otp: empty secret")
	}
	if pad := len(clean) % 8; pad != 0 {
		clean += strings.Repeat("=", 8-pad)
	}
	b, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("otp: secret is not valid base32: %w", err)
	}
	return b, nil
}

// DecodeSecretBase64 decodes a base64 2FA secret — the form Steam stores its
// shared_secret in (the maFile / loot form), as opposed to the base32 Google-
// Authenticator form. Standard and raw (unpadded) base64 are both accepted.
func DecodeSecretBase64(s string) ([]byte, error) {
	clean := strings.TrimSpace(s)
	if clean == "" {
		return nil, fmt.Errorf("otp: empty secret")
	}
	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("otp: secret is not valid base64: %w", err)
	}
	return b, nil
}
