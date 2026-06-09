// SPDX-License-Identifier: AGPL-3.0-or-later

package base58check_test

import (
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/xunholy/promptzero/internal/base58check"
)

// --- test-side Base58Check encoder, the inverse of the decoder, for round-trips.

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Encode(b []byte) string {
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	v := new(big.Int).SetBytes(b)
	radix := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for v.Sign() > 0 {
		v.DivMod(v, radix, mod)
		out = append(out, alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	// reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

// encodeCheck appends the correct double-SHA-256 checksum and Base58-encodes.
func encodeCheck(body []byte) string {
	h1 := sha256.Sum256(body)
	h2 := sha256.Sum256(h1[:])
	return base58Encode(append(append([]byte{}, body...), h2[:4]...))
}

// TestWIFCanonical anchors against the canonical Bitcoin WIF test vector.
func TestWIFCanonical(t *testing.T) {
	const (
		wif  = "5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ"
		priv = "0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d"
	)
	r, err := base58check.Decode(wif)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ChecksumValid {
		t.Errorf("checksum_valid = false, want true")
	}
	if r.Type != "WIF private key" || r.Network != "mainnet" {
		t.Errorf("Type/Network = %q/%q; want WIF private key/mainnet", r.Type, r.Network)
	}
	if r.PrivateKeyHex != priv {
		t.Errorf("private_key = %s; want %s", r.PrivateKeyHex, priv)
	}
	if r.Compressed == nil || *r.Compressed {
		t.Errorf("compressed = %v; want false", r.Compressed)
	}
	if r.VersionHex != "80" {
		t.Errorf("version = %s; want 80", r.VersionHex)
	}
}

// TestP2PKHCanonical anchors against Satoshi's genesis coinbase address.
func TestP2PKHCanonical(t *testing.T) {
	const (
		addr = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
		h160 = "62e907b15cbf27d5425399ebf6f0fb50ebb88f18"
	)
	r, err := base58check.Decode(addr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ChecksumValid {
		t.Errorf("checksum_valid = false, want true")
	}
	if r.Type != "P2PKH address" || r.Network != "mainnet" {
		t.Errorf("Type/Network = %q/%q; want P2PKH address/mainnet", r.Type, r.Network)
	}
	if r.VersionHex != "00" {
		t.Errorf("version = %s; want 00", r.VersionHex)
	}
	if r.PayloadHex != h160 {
		t.Errorf("hash160 = %s; want %s", r.PayloadHex, h160)
	}
}

// TestRoundTripTypes encodes each artifact class with a correct checksum and
// confirms the decoder identifies it — covering P2SH, testnet WIF, compressed
// WIF, and a BIP-32 extended key (with field parse).
func TestRoundTripTypes(t *testing.T) {
	priv32 := make([]byte, 32)
	for i := range priv32 {
		priv32[i] = byte(i + 1)
	}
	hash20 := make([]byte, 20)
	for i := range hash20 {
		hash20[i] = byte(0xa0 + i)
	}

	// P2SH mainnet (0x05).
	if r, _ := base58check.Decode(encodeCheck(append([]byte{0x05}, hash20...))); r.Type != "P2SH address" || r.Network != "mainnet" || !r.ChecksumValid {
		t.Errorf("P2SH: got %q/%q valid=%v", r.Type, r.Network, r.ChecksumValid)
	}
	// Testnet WIF uncompressed (0xEF + 32).
	if r, _ := base58check.Decode(encodeCheck(append([]byte{0xef}, priv32...))); r.Type != "WIF private key" || r.Network != "testnet" || r.Compressed == nil || *r.Compressed {
		t.Errorf("testnet WIF: got %q/%q compressed=%v", r.Type, r.Network, r.Compressed)
	}
	// Compressed WIF (0x80 + 32 + 0x01).
	body := append(append([]byte{0x80}, priv32...), 0x01)
	if r, _ := base58check.Decode(encodeCheck(body)); r.Compressed == nil || !*r.Compressed || r.PrivateKeyHex != "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20" {
		t.Errorf("compressed WIF: compressed=%v priv=%s", r.Compressed, r.PrivateKeyHex)
	}
	// BIP-32 xprv (0x0488ADE4) — 78-byte body.
	extBody := make([]byte, 78)
	extBody[0], extBody[1], extBody[2], extBody[3] = 0x04, 0x88, 0xad, 0xe4
	extBody[4] = 0x03  // depth
	extBody[9] = 0x00  // child number high byte
	extBody[12] = 0x05 // child number low byte → 5
	r, _ := base58check.Decode(encodeCheck(extBody))
	if r.Type != "BIP-32 extended private key (xprv)" || r.Network != "mainnet" {
		t.Errorf("xprv: type=%q network=%q", r.Type, r.Network)
	}
	if r.Extended == nil || r.Extended.Depth != 3 || r.Extended.ChildNumber != 5 {
		t.Errorf("xprv fields = %+v; want depth 3 child 5", r.Extended)
	}
}

// TestBadChecksumReported confirms a corrupted checksum is flagged, not errored.
func TestBadChecksumReported(t *testing.T) {
	body := append([]byte{0x00}, make([]byte, 20)...)
	good := encodeCheck(body)
	// Corrupt the checksum by appending a wrong 4-byte tail.
	bad := base58Encode(append(append([]byte{}, body...), []byte{0xde, 0xad, 0xbe, 0xef}...))
	r, err := base58check.Decode(bad)
	if err != nil {
		t.Fatalf("Decode(bad): %v", err)
	}
	if r.ChecksumValid {
		t.Errorf("checksum_valid = true, want false")
	}
	if r.Note == "" {
		t.Errorf("expected a Note flagging the bad checksum")
	}
	// Sanity: the good one validates.
	if g, _ := base58check.Decode(good); !g.ChecksumValid {
		t.Errorf("the correctly-checksummed string should validate")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"bad base58 char": "1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf0a", // contains '0'
		"too short":       "z",                                  // decodes to 1 byte (< version+checksum)
	}
	for name, in := range cases {
		if _, err := base58check.Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}
