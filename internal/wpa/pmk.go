// SPDX-License-Identifier: AGPL-3.0-or-later

// Package wpa derives the WPA/WPA2-PSK Pairwise Master Key (PMK) from a
// passphrase and SSID. It is an offline Wi-Fi pentest primitive: given a
// candidate passphrase and the target network name, compute the 256-bit PMK —
// the value an attacker precomputes to check against a captured 4-way handshake
// or PMKID (the basis of the hashcat 22000 / 16800 workflows). It complements
// the existing Wi-Fi tooling (wifi_pmkid_hc22000, which formats a hashcat line,
// and internal/rsn, which parses the PMKID from a beacon) by supplying the
// derivation step neither of those performs. Pure offline compute from
// operator-supplied strings; no network or device interaction.
//
// # Wrap-vs-native judgement
//
// Native. The PMK is PBKDF2-HMAC-SHA1(passphrase, SSID, 4096, 32) per IEEE
// 802.11i. PBKDF2 (RFC 2898) is a dozen lines of HMAC iteration over the
// standard library's crypto/hmac + crypto/sha1 — implemented here rather than
// pulled from golang.org/x/crypto/pbkdf2 to keep the crypto primitives owned
// in-tree, consistent with internal/otp, internal/hmacutil and internal/jwtsig
// (x/crypto is already an indirect dependency, so this is not about avoiding a
// new module — it is about owning the code).
//
// # Verifiable / no confidently-wrong output
//
// Strong verification class with two independent published anchors:
//   - PBKDF2-HMAC-SHA1 reproduces the RFC 6070 test vectors exactly
//     (P="password", S="salt", c=4096, dkLen=20 -> 4b007901b765489abead49d926…).
//   - DerivePMK reproduces the IEEE 802.11i Annex test vectors exactly
//     (passphrase "password", SSID "IEEE" ->
//     f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e).
//
// Both are gated in the unit tests, so the derivation ships only if it matches
// the authoritative references.
//
// # Covered / deferred
//
// Covered: the ASCII-passphrase PMK derivation (the overwhelmingly common case),
// with IEEE 802.11i input validation (passphrase 8-63 printable ASCII, SSID
// 1-32 bytes). Deferred: the 64-hex-character raw-PSK form (where the PMK is the
// hex itself, no PBKDF2), and PMKID computation (PMKID = HMAC-SHA1(PMK,
// "PMK Name"||AA||SPA) truncated to 16 bytes) — the algorithm is standard but is
// held back until gated against a confidently-sourced reference vector, since a
// wrong PMKID is worse than none.
package wpa

import (
	"crypto/hmac"
	"crypto/sha1" //nolint:gosec // WPA-PSK is PBKDF2-HMAC-SHA1 by IEEE 802.11i; this is the spec algorithm, not a security choice.
	"encoding/binary"
	"fmt"
	"hash"
)

const (
	pmkIterations = 4096 // IEEE 802.11i fixed iteration count for WPA-PSK.
	pmkLength     = 32   // 256-bit PMK.
)

// PBKDF2 implements RFC 2898 PBKDF2 over the given PRF hash, deriving keyLen
// bytes from password and salt with iter iterations.
func PBKDF2(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	t := make([]byte, hashLen)
	var blockIdx [4]byte
	for block := 1; block <= numBlocks; block++ {
		// U_1 = PRF(password, salt || INT_32_BE(block)).
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(blockIdx[:], uint32(block))
		prf.Write(blockIdx[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		// U_n = PRF(password, U_{n-1}); T = U_1 ^ U_2 ^ … ^ U_iter.
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for x := range t {
				t[x] ^= u[x]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

// DerivePMK derives the 32-byte WPA/WPA2-PSK Pairwise Master Key for the given
// passphrase and SSID per IEEE 802.11i: PBKDF2-HMAC-SHA1(passphrase, SSID, 4096,
// 32). The passphrase must be 8-63 printable-ASCII characters and the SSID 1-32
// bytes (the standard's constraints — input outside these ranges could never
// match a real access point, so it is rejected rather than silently producing a
// useless PMK).
func DerivePMK(passphrase, ssid string) ([]byte, error) {
	if l := len(passphrase); l < 8 || l > 63 {
		return nil, fmt.Errorf("wpa: passphrase must be 8-63 characters (got %d) per IEEE 802.11i", l)
	}
	for i := 0; i < len(passphrase); i++ {
		if passphrase[i] < 32 || passphrase[i] > 126 {
			return nil, fmt.Errorf("wpa: passphrase must be printable ASCII (byte 0x%02x at index %d is out of range)", passphrase[i], i)
		}
	}
	if l := len(ssid); l < 1 || l > 32 {
		return nil, fmt.Errorf("wpa: SSID must be 1-32 bytes (got %d)", l)
	}
	return PBKDF2([]byte(passphrase), []byte(ssid), pmkIterations, pmkLength, sha1.New), nil
}
