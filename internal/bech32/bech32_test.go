// SPDX-License-Identifier: AGPL-3.0-or-later

package bech32_test

import (
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/bech32"
)

// --- test-side Bech32/Bech32m encoder, the inverse of the decoder, for round-trips.

const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

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

func encode(hrp string, data []int, bech32m bool) string {
	cst := 1
	if bech32m {
		cst = 0x2bc830a3
	}
	values := append(hrpExpand(hrp), data...)
	values = append(values, 0, 0, 0, 0, 0, 0)
	mod := polymod(values) ^ cst
	checksum := make([]int, 6)
	for i := 0; i < 6; i++ {
		checksum[i] = (mod >> uint(5*(5-i))) & 31
	}
	var sb strings.Builder
	sb.WriteString(hrp)
	sb.WriteByte('1')
	for _, d := range append(append([]int{}, data...), checksum...) {
		sb.WriteByte(charset[d])
	}
	return sb.String()
}

// convertBits 8→5 for building SegWit program payloads.
func to5(b []byte) []int {
	acc, bits := 0, 0
	var out []int
	for _, v := range b {
		acc = acc<<8 | int(v)
		bits += 8
		for bits >= 5 {
			bits -= 5
			out = append(out, (acc>>uint(bits))&31)
		}
	}
	if bits > 0 {
		out = append(out, (acc<<uint(5-bits))&31)
	}
	return out
}

// TestBIPChecksumVectors anchors both checksum variants against the BIP-173 /
// BIP-350 empty-data test vectors.
func TestBIPChecksumVectors(t *testing.T) {
	cases := []struct {
		s       string
		variant string
	}{
		{"A12UEL5L", "bech32"},
		{"a12uel5l", "bech32"},
		{"A1LQFN3A", "bech32m"},
	}
	for _, tc := range cases {
		r, err := bech32.Decode(tc.s)
		if err != nil {
			t.Fatalf("Decode(%q): %v", tc.s, err)
		}
		if !r.ChecksumValid || r.Variant != tc.variant {
			t.Errorf("%q: variant=%q valid=%v; want %s valid", tc.s, r.Variant, r.ChecksumValid, tc.variant)
		}
		if r.HRP != "a" {
			t.Errorf("%q: HRP=%q; want a", tc.s, r.HRP)
		}
	}
}

// TestP2WPKHVector anchors SegWit v0 decoding against the canonical BIP-173
// P2WPKH address.
func TestP2WPKHVector(t *testing.T) {
	const (
		addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
		prog = "751e76e8199196d454941c45d1b3a323f1433bd6"
	)
	r, err := bech32.Decode(addr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ChecksumValid || r.Variant != "bech32" {
		t.Errorf("variant=%q valid=%v; want bech32 valid", r.Variant, r.ChecksumValid)
	}
	if r.HRP != "bc" {
		t.Errorf("HRP=%q; want bc", r.HRP)
	}
	if r.WitnessVersion == nil || *r.WitnessVersion != 0 {
		t.Errorf("witness_version = %v; want 0", r.WitnessVersion)
	}
	if r.WitnessProgramHex != prog {
		t.Errorf("program = %s; want %s", r.WitnessProgramHex, prog)
	}
	if r.Type != "P2WPKH (SegWit v0)" {
		t.Errorf("type = %q; want P2WPKH (SegWit v0)", r.Type)
	}
}

// TestTaprootRoundTrip builds a SegWit v1 (Taproot) address with the test
// encoder and confirms it decodes as Bech32m / P2TR — covering the v1+ variant
// rule without a hardcoded address string.
func TestTaprootRoundTrip(t *testing.T) {
	prog := make([]byte, 32)
	for i := range prog {
		prog[i] = byte(i)
	}
	data := append([]int{1}, to5(prog)...) // witness version 1 + program
	addr := encode("bc", data, true)       // Taproot uses bech32m

	r, err := bech32.Decode(addr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ChecksumValid || r.Variant != "bech32m" {
		t.Errorf("variant=%q valid=%v; want bech32m valid", r.Variant, r.ChecksumValid)
	}
	if r.WitnessVersion == nil || *r.WitnessVersion != 1 || r.Type != "P2TR (Taproot, SegWit v1)" {
		t.Errorf("v1 program: version=%v type=%q", r.WitnessVersion, r.Type)
	}
}

// TestWrongVariantFlagged confirms a v0 address mistakenly using Bech32m (or a
// generally bad checksum) is flagged, not asserted valid.
func TestWrongVariantFlagged(t *testing.T) {
	prog := make([]byte, 20)
	data := append([]int{0}, to5(prog)...)
	// Encode a v0 program with the WRONG (bech32m) checksum.
	addr := encode("bc", data, true)
	r, err := bech32.Decode(addr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	// Checksum is internally consistent as bech32m, but v0 requires bech32.
	if r.Variant != "bech32m" {
		t.Errorf("variant = %q; want bech32m", r.Variant)
	}
	if r.Note == "" || !strings.Contains(r.Note, "v0 must use Bech32") {
		t.Errorf("expected a v0-must-use-Bech32 note, got %q", r.Note)
	}
}

// TestNostrLabel confirms a non-Bitcoin HRP is labelled and the payload decoded.
func TestNostrLabel(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(0x10 + i)
	}
	addr := encode("npub", to5(pub), false)
	r, err := bech32.Decode(addr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Type != "Nostr public key" {
		t.Errorf("type = %q; want Nostr public key", r.Type)
	}
	if r.DataHex != "101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f" {
		t.Errorf("data_hex = %s", r.DataHex)
	}
}

func TestBadChecksumReported(t *testing.T) {
	// A valid string with one data char changed → checksum fails.
	r, err := bech32.Decode("a12uel5p") // last data char 'l'→'p'
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ChecksumValid || r.Variant != "invalid" {
		t.Errorf("variant=%q valid=%v; want invalid", r.Variant, r.ChecksumValid)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"too short":      "a1bcd",
		"no separator":   "abcdefghij",
		"mixed case":     "A12uel5l",
		"bad data char":  "a12uebl5l", // 'b' is not in the charset at that spot... actually 'b' invalid
		"hrp only / sep": "1qqqqqqqq",
	}
	for name, in := range cases {
		if _, err := bech32.Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}
