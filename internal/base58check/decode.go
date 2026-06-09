// SPDX-License-Identifier: AGPL-3.0-or-later

// Package base58check decodes a Base58Check string — the encoding Bitcoin (and
// many forks / chains) use for WIF private keys, legacy addresses, and BIP-32
// extended keys — into its version, payload, and checksum validity, and
// identifies the artifact type. A leaked WIF private key, address, or xprv/xpub
// is common crypto-forensics / IR / pentest loot; decoding one offline (and
// confirming its checksum) is the natural companion to bip39_decode. Pure
// offline transform; no network or device.
//
// # Wrap-vs-native judgement
//
// Native. Base58Check is a public encoding: a base-58 integer conversion, a
// 4-byte double-SHA-256 checksum, and a version-byte prefix — math/big +
// crypto/sha256, nothing to wrap.
//
// # What this covers / defers
//
//   - 1-byte-version artifacts: P2PKH (0x00 mainnet / 0x6F testnet), P2SH
//     (0x05 / 0xC4), and WIF private keys (0x80 / 0xEF) — the WIF case
//     surfaces the 32-byte private key and the compressed flag.
//   - 4-byte-version BIP-32 extended keys (xprv/xpub, tprv/tpub) — identified
//     and field-parsed (depth, parent fingerprint, child number, chain code,
//     key) from the fixed 78-byte body.
//   - Bech32 (segwit bc1…/tb1…) is a DIFFERENT encoding, not Base58Check, and
//     is out of scope here (a separate decoder).
//   - An unknown version byte is surfaced raw ("unknown") rather than guessed.
//
// # Verifiable / no confidently-wrong output
//
// Anchored to the canonical Bitcoin vectors — the WIF
// 5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ → private key
// 0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D, and the
// genesis address 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa → hash160
// 62E907B15CBF27D5425399EBF6F0FB50EBB88F18. A string whose 4-byte
// double-SHA-256 checksum does not validate is reported as such (likely a typo
// or truncation) rather than asserted genuine; a non-Base58 character or a
// too-short decode is rejected.
package base58check

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
)

// alphabet is the Bitcoin Base58 alphabet (no 0, O, I, l).
const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// b58Index maps each byte to its Base58 value, or -1.
var b58Index = func() [256]int {
	var idx [256]int
	for i := range idx {
		idx[i] = -1
	}
	for i := 0; i < len(alphabet); i++ {
		idx[alphabet[i]] = i
	}
	return idx
}()

// ExtendedKey holds the parsed fields of a BIP-32 extended key (when the
// decoded artifact is one).
type ExtendedKey struct {
	Depth             int    `json:"depth"`
	ParentFingerprint string `json:"parent_fingerprint"` // 4-byte hex
	ChildNumber       uint32 `json:"child_number"`
	ChainCodeHex      string `json:"chain_code_hex"` // 32-byte hex
	KeyHex            string `json:"key_hex"`        // 33-byte hex (0x00||priv for xprv, compressed pub for xpub)
}

// Result is the decoded view of a Base58Check string.
type Result struct {
	Input         string `json:"input"`
	Type          string `json:"type"`              // identified artifact, or "unknown"
	Network       string `json:"network,omitempty"` // mainnet / testnet
	VersionHex    string `json:"version_hex"`       // 1- or 4-byte version, hex
	PayloadHex    string `json:"payload_hex"`
	ChecksumValid bool   `json:"checksum_valid"`
	// WIF-specific.
	PrivateKeyHex string `json:"private_key_hex,omitempty"`
	Compressed    *bool  `json:"compressed,omitempty"`
	// BIP-32 extended-key fields (when Type is an extended key).
	Extended *ExtendedKey `json:"extended,omitempty"`
	Note     string       `json:"note,omitempty"`
}

// Decode decodes a Base58Check string, validates its double-SHA-256 checksum,
// and identifies the artifact. A bad Base58 character or a too-short decode is
// an error; a non-validating checksum is reported (not an error).
func Decode(s string) (*Result, error) {
	in := strings.TrimSpace(s)
	raw, err := base58Decode(in)
	if err != nil {
		return nil, err
	}
	if len(raw) < 5 {
		return nil, fmt.Errorf("base58check: decoded %d bytes — too short for a version + 4-byte checksum", len(raw))
	}
	body := raw[:len(raw)-4]
	gotSum := raw[len(raw)-4:]
	wantSum := doubleSHA256(body)[:4]
	res := &Result{
		Input:         in,
		ChecksumValid: bytes.Equal(gotSum, wantSum),
	}
	identify(res, body)
	if !res.ChecksumValid {
		res.Note = "checksum does not validate — likely a typo, truncation, or not a Base58Check string; " +
			"fields are surfaced from the bytes as decoded"
	}
	return res, nil
}

// identify fills in the type-specific fields from the version-tagged body.
func identify(res *Result, body []byte) {
	// 4-byte-version BIP-32 extended keys have an exact 78-byte body.
	if len(body) == 78 {
		ver := binary.BigEndian.Uint32(body[:4])
		if name, network, ok := extKeyVersion(ver); ok {
			res.Type = name
			res.Network = network
			res.VersionHex = hex.EncodeToString(body[:4])
			res.PayloadHex = hex.EncodeToString(body[4:])
			res.Extended = &ExtendedKey{
				Depth:             int(body[4]),
				ParentFingerprint: hex.EncodeToString(body[5:9]),
				ChildNumber:       binary.BigEndian.Uint32(body[9:13]),
				ChainCodeHex:      hex.EncodeToString(body[13:45]),
				KeyHex:            hex.EncodeToString(body[45:78]),
			}
			return
		}
	}

	version := body[0]
	payload := body[1:]
	res.VersionHex = fmt.Sprintf("%02x", version)
	res.PayloadHex = hex.EncodeToString(payload)

	switch version {
	case 0x00:
		res.Type, res.Network = "P2PKH address", "mainnet"
	case 0x05:
		res.Type, res.Network = "P2SH address", "mainnet"
	case 0x6f:
		res.Type, res.Network = "P2PKH address", "testnet"
	case 0xc4:
		res.Type, res.Network = "P2SH address", "testnet"
	case 0x80:
		res.Type, res.Network = "WIF private key", "mainnet"
		fillWIF(res, payload)
	case 0xef:
		res.Type, res.Network = "WIF private key", "testnet"
		fillWIF(res, payload)
	default:
		res.Type = "unknown"
	}
}

// fillWIF surfaces the private key and compression flag from a WIF payload: 32
// bytes (uncompressed) or 33 bytes with a trailing 0x01 (compressed).
func fillWIF(res *Result, payload []byte) {
	switch {
	case len(payload) == 33 && payload[32] == 0x01:
		t := true
		res.Compressed = &t
		res.PrivateKeyHex = hex.EncodeToString(payload[:32])
	case len(payload) == 32:
		f := false
		res.Compressed = &f
		res.PrivateKeyHex = hex.EncodeToString(payload)
	default:
		// Non-standard WIF length — leave the raw payload, flag via Note.
		res.Note = fmt.Sprintf("WIF version byte but %d-byte payload (expected 32 or 33)", len(payload))
	}
}

// extKeyVersion maps the known BIP-32 extended-key version prefixes.
func extKeyVersion(v uint32) (name, network string, ok bool) {
	switch v {
	case 0x0488ade4:
		return "BIP-32 extended private key (xprv)", "mainnet", true
	case 0x0488b21e:
		return "BIP-32 extended public key (xpub)", "mainnet", true
	case 0x04358394:
		return "BIP-32 extended private key (tprv)", "testnet", true
	case 0x043587cf:
		return "BIP-32 extended public key (tpub)", "testnet", true
	default:
		return "", "", false
	}
}

// doubleSHA256 returns SHA-256(SHA-256(b)).
func doubleSHA256(b []byte) []byte {
	h1 := sha256.Sum256(b)
	h2 := sha256.Sum256(h1[:])
	return h2[:]
}

// base58Decode decodes a Base58 string to bytes, preserving leading-'1' →
// leading-zero-byte semantics.
func base58Decode(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("base58check: empty input")
	}
	zeros := 0
	for zeros < len(s) && s[zeros] == '1' {
		zeros++
	}
	v := new(big.Int)
	radix := big.NewInt(58)
	for i := 0; i < len(s); i++ {
		d := b58Index[s[i]]
		if d < 0 {
			return nil, fmt.Errorf("base58check: invalid Base58 character %q at position %d", string(s[i]), i)
		}
		v.Mul(v, radix)
		v.Add(v, big.NewInt(int64(d)))
	}
	dec := v.Bytes()
	out := make([]byte, zeros+len(dec))
	copy(out[zeros:], dec)
	return out, nil
}
