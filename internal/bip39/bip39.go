// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bip39 validates and decodes a BIP-39 mnemonic — the 12/15/18/21/24-word
// "seed phrase" used by virtually every cryptocurrency wallet (Bitcoin, Ethereum,
// hardware wallets) — into its entropy, checksum validity, word indices, and the
// derived BIP-39 seed. A captured seed phrase is prime forensic / IR / pentest
// loot: it is the root secret from which every wallet key descends, so validating
// one (real mnemonic vs. typo / wrong order / non-wordlist word) and deriving its
// seed is a high-value offline step. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. BIP-39 is a public specification: 11-bit word indices over the embedded
// 2048-word list, a SHA-256 checksum over the entropy, and a PBKDF2-HMAC-SHA512
// seed derivation — all stdlib crypto + the in-tree internal/wpa.PBKDF2 (no new
// runtime dependency; x/text's NFKD normaliser was already an indirect module
// dependency). Nothing is wrapped or shelled out.
//
// # What this covers / defers
//
//   - English wordlist only (the default and overwhelmingly most common; the
//     embedded english.txt is the official BIP-39 list, SHA-256
//     2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda). Other
//     language lists are deferred — a phrase is rejected as "not in the wordlist"
//     rather than guessed against a list we did not validate.
//   - Validation (word count, every word in the list, SHA-256 checksum) and seed
//     derivation. BIP-32 master-key / address derivation from the seed is a
//     separate, larger surface left to the caller.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the official Trezor BIP-39 test vectors (e.g. the all-"abandon …
// about" mnemonic → entropy 00000000000000000000000000000000, and with
// passphrase "TREZOR" → seed c55257c3…7463b04). A phrase whose checksum does not
// validate is reported as such (likely a typo / wrong order) rather than asserted
// as a genuine mnemonic; the seed is still derived from the words as given (BIP-39
// derives a seed from any phrase) but clearly flagged. A non-wordlist word or an
// invalid word count is rejected.
package bip39

import (
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/wpa"
	"golang.org/x/text/unicode/norm"
)

//go:embed english.txt
var englishList string

// words is the ordered 2048-word English list; wordIndex is its inverse.
var (
	words     []string
	wordIndex map[string]int
)

func init() { //nolint:gochecknoinits
	words = strings.Fields(englishList)
	wordIndex = make(map[string]int, len(words))
	for i, w := range words {
		wordIndex[w] = i
	}
}

// WordCount returns the number of words in the embedded list (2048). Exposed for
// the package's own invariant test.
func WordCount() int { return len(words) }

// Result is the decoded view of a BIP-39 mnemonic.
type Result struct {
	// WordCount is the mnemonic length (12/15/18/21/24).
	WordCount int `json:"word_count"`
	// EntropyBits is the entropy strength (128/160/192/224/256).
	EntropyBits int `json:"entropy_bits"`
	// EntropyHex is the recovered entropy, lowercase hex.
	EntropyHex string `json:"entropy_hex"`
	// ChecksumValid is true when the trailing checksum bits match SHA-256 of the
	// entropy — i.e. this is a genuine BIP-39 mnemonic, not a typo'd phrase.
	ChecksumValid bool `json:"checksum_valid"`
	// Indices is the 11-bit list index of each word, in order.
	Indices []int `json:"indices"`
	// SeedHex is the 64-byte BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic,
	// "mnemonic"+passphrase, 2048). Derived from the words as given regardless of
	// checksum validity (per BIP-39).
	SeedHex string `json:"seed_hex"`
	// Note flags a non-validating checksum.
	Note string `json:"note,omitempty"`
}

// validCounts is the set of permitted mnemonic lengths.
var validCounts = map[int]bool{12: true, 15: true, 18: true, 21: true, 24: true}

// Decode validates the mnemonic against the embedded English wordlist, recovers
// its entropy, checks the SHA-256 checksum, and derives the BIP-39 seed (with the
// optional passphrase). A bad word count or a non-wordlist word is an error; a
// non-validating checksum is reported (not an error) so the operator still gets
// the entropy and seed of a near-miss phrase.
func Decode(mnemonic, passphrase string) (*Result, error) {
	// BIP-39 normalises both the mnemonic and the passphrase to NFKD. The English
	// wordlist is lowercase ASCII, so lowercasing the mnemonic also makes lookup
	// case-insensitive without affecting the canonical vectors. The passphrase is
	// case-sensitive and is NOT lowercased.
	mnNorm := strings.ToLower(norm.NFKD.String(strings.TrimSpace(mnemonic)))
	ws := strings.Fields(mnNorm)
	n := len(ws)
	if n == 0 {
		return nil, fmt.Errorf("bip39: empty mnemonic")
	}
	if !validCounts[n] {
		return nil, fmt.Errorf("bip39: %d words; a BIP-39 mnemonic must be 12, 15, 18, 21, or 24 words", n)
	}

	indices := make([]int, n)
	var unknown []string
	for i, w := range ws {
		idx, ok := wordIndex[w]
		if !ok {
			unknown = append(unknown, w)
			continue
		}
		indices[i] = idx
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("bip39: %d word(s) not in the BIP-39 English wordlist: %s",
			len(unknown), strings.Join(unknown, ", "))
	}

	// Lay the 11-bit indices out MSB-first into a bit slice of length n*11.
	totalBits := n * 11
	entBits := totalBits / 33 * 32 // ENT = MS*32/33
	csBits := totalBits - entBits  // CS  = ENT/32
	bits := make([]byte, totalBits)
	for i, idx := range indices {
		for b := 0; b < 11; b++ {
			bits[i*11+b] = byte((idx >> uint(10-b)) & 1)
		}
	}

	// Pack the entropy bits into bytes.
	entBytes := make([]byte, entBits/8)
	for i := 0; i < entBits; i++ {
		if bits[i] == 1 {
			entBytes[i/8] |= 1 << uint(7-(i%8))
		}
	}

	// The checksum is the first csBits of SHA-256(entropy).
	digest := sha256.Sum256(entBytes)
	checksumValid := true
	for i := 0; i < csBits; i++ {
		want := (digest[i/8] >> uint(7-(i%8))) & 1
		if bits[entBits+i] != want {
			checksumValid = false
			break
		}
	}

	// BIP-39 seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic"+passphrase, 2048, 64).
	// The mnemonic password is the single-space-joined NFKD form.
	password := strings.Join(ws, " ")
	salt := "mnemonic" + norm.NFKD.String(passphrase)
	seed := wpa.PBKDF2([]byte(password), []byte(salt), 2048, 64, sha512.New)

	res := &Result{
		WordCount:     n,
		EntropyBits:   entBits,
		EntropyHex:    hex.EncodeToString(entBytes),
		ChecksumValid: checksumValid,
		Indices:       indices,
		SeedHex:       hex.EncodeToString(seed),
	}
	if !checksumValid {
		res.Note = "checksum does not validate — not a genuine BIP-39 mnemonic (likely a typo, " +
			"wrong word, or wrong order); the seed is still derived from the words as given"
	}
	return res, nil
}
