// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bech32 decodes a Bech32 / Bech32m string — the encoding modern Bitcoin
// uses for SegWit addresses (bc1…/tb1…), and which Nostr (npub/nsec/note),
// Lightning (lnbc…), and Cosmos-family chains also use — into its human-readable
// prefix (HRP), data payload, and checksum variant, and interprets SegWit
// addresses (witness version + program + type). It is the Bech32 companion to
// base58check_decode, closing out Bitcoin-address coverage for crypto-forensics
// / IR / pentest loot. Pure offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. Bech32 is a public spec (BIP-173 / BIP-350): a base-32 charset, a BCH
// checksum over the polynomial defined there (constant 1 for Bech32, 0x2bc830a3
// for Bech32m), and a 5-bit↔8-bit regrouping — pure integer maths, stdlib only,
// nothing to wrap.
//
// # What this covers / defers
//
//   - General Bech32 and Bech32m decode: HRP, the 5→8-bit data payload, and the
//     checksum variant — works for any HRP (Bitcoin, Nostr, Lightning, Cosmos…).
//   - SegWit address interpretation for the bc/tb/bcrt HRPs: witness version,
//     witness program, and the address type (P2WPKH / P2WSH / P2TR), with the
//     BIP-173/350 variant rule enforced (v0 ⇒ Bech32, v1+ ⇒ Bech32m).
//   - Nostr (npub/nsec/note) and Lightning (lnbc…) HRPs are labelled; their
//     inner TLV / invoice structure is left to the caller (a separate surface).
//   - Base58Check (legacy 1…/3… addresses, WIF) is the other encoding — see
//     base58check_decode.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the BIP-173 / BIP-350 test vectors — A12UEL5L (Bech32, HRP "a"),
// A1LQFN3A (Bech32m, HRP "a"), and the P2WPKH address
// bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 → witness v0, program
// 751e76e8199196d454941c45d1b3a323f1433bd6. A string whose checksum does not
// validate, or a SegWit address whose variant does not match its witness
// version, is reported as such rather than asserted valid; mixed-case input, a
// missing separator, or an out-of-charset character is rejected.
package bech32

import (
	"encoding/hex"
	"fmt"
	"strings"
)

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

var charsetRev = func() [256]int {
	var r [256]int
	for i := range r {
		r[i] = -1
	}
	for i := 0; i < len(charset); i++ {
		r[charset[i]] = i
	}
	return r
}()

// Bech32 / Bech32m checksum constants (BIP-173 / BIP-350).
const (
	constBech32  = 1
	constBech32m = 0x2bc830a3
)

// Result is the decoded view of a Bech32/Bech32m string.
type Result struct {
	Input         string `json:"input"`
	HRP           string `json:"hrp"`
	Variant       string `json:"variant"` // "bech32" / "bech32m" / "invalid"
	ChecksumValid bool   `json:"checksum_valid"`
	// DataHex is the data payload regrouped from 5-bit to 8-bit (when it is
	// byte-aligned). Empty for an empty or non-byte-aligned payload.
	DataHex string `json:"data_hex,omitempty"`
	// Type labels a recognised artifact (SegWit address class, Nostr, Lightning).
	Type string `json:"type,omitempty"`
	// SegWit fields (set when the HRP is a SegWit network).
	WitnessVersion    *int   `json:"witness_version,omitempty"`
	WitnessProgramHex string `json:"witness_program_hex,omitempty"`
	Note              string `json:"note,omitempty"`
}

// Decode parses and checksums a Bech32/Bech32m string and interprets SegWit
// addresses. A structural error (mixed case, no separator, bad charset, bad
// length) is returned as an error; a bad checksum or a SegWit-rule violation is
// reported in the Result.
func Decode(input string) (*Result, error) {
	s := strings.TrimSpace(input)
	if len(s) < 8 || len(s) > 90 {
		return nil, fmt.Errorf("bech32: length %d out of range (8-90)", len(s))
	}
	lower, upper := strings.ToLower(s), strings.ToUpper(s)
	if s != lower && s != upper {
		return nil, fmt.Errorf("bech32: mixed-case strings are not allowed")
	}
	s = lower

	pos := strings.LastIndexByte(s, '1')
	if pos < 1 || pos+7 > len(s) {
		return nil, fmt.Errorf("bech32: missing or misplaced '1' separator")
	}
	hrp := s[:pos]
	dataPart := s[pos+1:]
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return nil, fmt.Errorf("bech32: HRP character out of range at %d", i)
		}
	}

	data := make([]int, len(dataPart))
	for i := 0; i < len(dataPart); i++ {
		v := charsetRev[dataPart[i]]
		if v < 0 {
			return nil, fmt.Errorf("bech32: invalid data character %q at position %d", string(dataPart[i]), i)
		}
		data[i] = v
	}

	res := &Result{Input: input, HRP: hrp}
	switch polymod(append(hrpExpand(hrp), data...)) {
	case constBech32:
		res.Variant, res.ChecksumValid = "bech32", true
	case constBech32m:
		res.Variant, res.ChecksumValid = "bech32m", true
	default:
		res.Variant, res.ChecksumValid = "invalid", false
		res.Note = "checksum does not validate — likely a typo, truncation, or not a Bech32 string"
	}

	payload := data[:len(data)-6] // strip the 6-symbol checksum
	if b, ok := convertBits(payload, 5, 8, false); ok && len(b) > 0 {
		res.DataHex = hex.EncodeToString(b)
	}

	interpret(res, hrp, payload)
	return res, nil
}

// interpret labels recognised artifacts and decodes SegWit addresses.
func interpret(res *Result, hrp string, payload []int) {
	switch hrp {
	case "bc", "tb", "bcrt":
		decodeSegwit(res, payload)
		return
	}
	switch {
	case hrp == "npub":
		res.Type = "Nostr public key"
	case hrp == "nsec":
		res.Type = "Nostr private key"
	case hrp == "note":
		res.Type = "Nostr note id"
	case strings.HasPrefix(hrp, "nprofile"), strings.HasPrefix(hrp, "nevent"),
		strings.HasPrefix(hrp, "naddr"), strings.HasPrefix(hrp, "nrelay"):
		res.Type = "Nostr entity (TLV)"
	case strings.HasPrefix(hrp, "lnbc"), strings.HasPrefix(hrp, "lntb"),
		strings.HasPrefix(hrp, "lnbcrt"), strings.HasPrefix(hrp, "lntbs"):
		res.Type = "Lightning invoice"
	}
}

// decodeSegwit interprets a SegWit address payload: witness version + program,
// with the BIP-173/350 variant and length rules.
func decodeSegwit(res *Result, payload []int) {
	if len(payload) < 1 {
		res.Note = "SegWit HRP but empty data"
		return
	}
	ver := payload[0]
	if ver > 16 {
		res.Note = fmt.Sprintf("invalid witness version %d (must be 0-16)", ver)
		return
	}
	prog, ok := convertBits(payload[1:], 5, 8, false)
	if !ok {
		res.Note = "witness program is not byte-aligned"
		return
	}
	if len(prog) < 2 || len(prog) > 40 {
		res.Note = fmt.Sprintf("witness program length %d out of range (2-40)", len(prog))
		return
	}
	res.WitnessVersion = &ver
	res.WitnessProgramHex = hex.EncodeToString(prog)

	// Variant rule: v0 uses Bech32; v1+ uses Bech32m.
	wantBech32m := ver != 0
	if wantBech32m && res.Variant != "bech32m" {
		res.Note = "witness v1+ must use Bech32m"
	} else if !wantBech32m && res.Variant != "bech32" {
		res.Note = "witness v0 must use Bech32"
	}

	switch {
	case ver == 0 && len(prog) == 20:
		res.Type = "P2WPKH (SegWit v0)"
	case ver == 0 && len(prog) == 32:
		res.Type = "P2WSH (SegWit v0)"
	case ver == 1 && len(prog) == 32:
		res.Type = "P2TR (Taproot, SegWit v1)"
	default:
		res.Type = fmt.Sprintf("SegWit v%d", ver)
	}
}

// polymod is the BIP-173 BCH checksum polynomial.
func polymod(values []int) int {
	gen := [5]int{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}
	chk := 1
	for _, v := range values {
		b := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ v
		for i := 0; i < 5; i++ {
			if (b>>uint(i))&1 == 1 {
				chk ^= gen[i]
			}
		}
	}
	return chk
}

// hrpExpand expands the HRP for the checksum: high bits, a 0 separator, low bits.
func hrpExpand(hrp string) []int {
	out := make([]int, 0, len(hrp)*2+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, int(hrp[i])&31)
	}
	return out
}

// convertBits regroups a base-2^fromBits stream into base-2^toBits. With pad
// false it fails when there are non-zero leftover bits (a strictness the SegWit
// program decode requires).
func convertBits(data []int, fromBits, toBits int, pad bool) ([]byte, bool) {
	acc, bits := 0, 0
	maxv := (1 << uint(toBits)) - 1
	var out []byte
	for _, v := range data {
		if v < 0 || v>>uint(fromBits) != 0 {
			return nil, false
		}
		acc = acc<<uint(fromBits) | v
		bits += fromBits
		for bits >= toBits {
			bits -= toBits
			out = append(out, byte((acc>>uint(bits))&maxv))
		}
	}
	if pad {
		if bits > 0 {
			out = append(out, byte((acc<<uint(toBits-bits))&maxv))
		}
	} else if bits >= fromBits || (acc<<uint(toBits-bits))&maxv != 0 {
		return nil, false
	}
	return out, true
}
