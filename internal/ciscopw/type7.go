// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ciscopw decodes Cisco IOS "type 7" passwords — the weak, reversible
// obfuscation produced by `service password-encryption`, ubiquitous in router
// and switch configuration loot. Unlike a hash, type 7 is fully reversible: a
// fixed-key XOR with a leading salt index, so the plaintext is recovered
// directly (no cracking). It complements hash_identify's Cisco type 8/9
// detection (those are real KDFs that must be cracked; type 7 is just decoded).
//
// # Wrap-vs-native judgement
//
// Native. The algorithm is a published 53-byte XOR key and a 2-digit decimal
// salt offset — a dozen lines of XOR. Every cisco7 tool (ciscot7, the Metasploit
// module) uses the same key; there is nothing to wrap.
//
// # Verifiable / no confidently-wrong output
//
// The key and algorithm are pinned by published vectors: "02050D480809" and
// "060506324F41" (different salts) both decode to "cisco", asserted in the unit
// tests, and Encode->Decode round-trips. A malformed input (odd length, a salt
// index past the key, non-hex bytes) is rejected rather than mis-decoded.
//
// # Covered / deferred
//
// Covered: type 7 decode + encode (for round-trip / config-crafting), and type
// 8 compute + verify (PBKDF2-HMAC-SHA256, the modern `secret` algorithm — see
// type8.go). Type 5 (md5crypt) is covered by internal/unixcrypt. Type 9
// (scrypt) is deliberately deferred: even though golang.org/x/crypto/scrypt is
// now a project dependency, the obvious scrypt(N=16384,r=1,p=1,keylen=32)
// construction does NOT reproduce the canonical hashcat-9300 example vector
// (the first 21 of 32 bytes match then diverge — an unresolved construction
// subtlety), so emitting a type-9 hash would be confidently-wrong. hash_identify
// flags $9$ for cracking instead.
package ciscopw

import (
	"fmt"
	"strconv"
	"strings"
)

// key is the fixed Cisco type-7 XOR key (Vigenère-style), pinned by the test
// vectors below.
const key = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"

// DecodeType7 recovers the plaintext of a Cisco IOS type-7 password. The first
// two characters are a decimal salt (the offset into the key); each subsequent
// hex byte is XORed with the key at the running offset.
func DecodeType7(enc string) (string, error) {
	enc = strings.TrimSpace(enc)
	if len(enc) < 2 {
		return "", fmt.Errorf("ciscopw: type-7 value too short (need at least the 2-digit salt)")
	}
	if len(enc)%2 != 0 {
		return "", fmt.Errorf("ciscopw: type-7 value has odd length %d (salt + hex byte pairs expected)", len(enc))
	}
	salt, err := strconv.Atoi(enc[0:2])
	if err != nil {
		return "", fmt.Errorf("ciscopw: salt %q is not a 2-digit number", enc[0:2])
	}
	if salt < 0 || salt >= len(key) {
		return "", fmt.Errorf("ciscopw: salt %d out of range 0-%d", salt, len(key)-1)
	}
	var sb strings.Builder
	for i := 2; i < len(enc); i += 2 {
		b, err := strconv.ParseUint(enc[i:i+2], 16, 8)
		if err != nil {
			return "", fmt.Errorf("ciscopw: %q is not a hex byte", enc[i:i+2])
		}
		idx := (salt + (i-2)/2) % len(key)
		sb.WriteByte(byte(b) ^ key[idx])
	}
	return sb.String(), nil
}

// EncodeType7 produces a Cisco type-7 value for a plaintext at the given salt
// (0..len(key)-1) — the inverse of DecodeType7, for round-trip checks and
// config crafting.
func EncodeType7(plain string, salt int) (string, error) {
	if salt < 0 || salt >= len(key) {
		return "", fmt.Errorf("ciscopw: salt %d out of range 0-%d", salt, len(key)-1)
	}
	sb := strings.Builder{}
	fmt.Fprintf(&sb, "%02d", salt)
	for i := 0; i < len(plain); i++ {
		idx := (salt + i) % len(key)
		fmt.Fprintf(&sb, "%02X", plain[i]^key[idx])
	}
	return sb.String(), nil
}
