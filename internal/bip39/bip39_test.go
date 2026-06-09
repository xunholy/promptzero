// SPDX-License-Identifier: AGPL-3.0-or-later

package bip39_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"testing"

	"github.com/xunholy/promptzero/internal/bip39"
)

// wordlist reads and parses english.txt independently of the package's own
// parsed list, so the round-trip encoder is a genuine cross-check.
func wordlist(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("english.txt")
	if err != nil {
		t.Fatalf("read english.txt: %v", err)
	}
	w := strings.Fields(string(b))
	if len(w) != 2048 {
		t.Fatalf("english.txt has %d words; want 2048", len(w))
	}
	return w
}

// TestWordlistInvariant pins the embedded list at exactly 2048 words — a wrong
// count would silently shift every index.
func TestWordlistInvariant(t *testing.T) {
	if n := bip39.WordCount(); n != 2048 {
		t.Fatalf("embedded wordlist has %d words; want 2048", n)
	}
}

// TestTrezorVectors anchors the decoder to the official Trezor BIP-39 test
// vectors (github.com/trezor/python-mnemonic, passphrase "TREZOR") — entropy,
// checksum validity, and the PBKDF2-HMAC-SHA512 seed, byte-for-byte. These two
// 128-bit vectors are the external ground truth; the round-trip test below
// covers the other lengths.
func TestTrezorVectors(t *testing.T) {
	cases := []struct {
		mnemonic string
		entropy  string
		seed     string
	}{
		{
			"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
			"00000000000000000000000000000000",
			"c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
		},
		{
			"legal winner thank year wave sausage worth useful legal winner thank yellow",
			"7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
			"2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
		},
	}
	for _, tc := range cases {
		r, err := bip39.Decode(tc.mnemonic, "TREZOR")
		if err != nil {
			t.Fatalf("Decode: %v", err)
		}
		if !r.ChecksumValid {
			t.Errorf("%q: checksum_valid = false, want true", tc.entropy)
		}
		if r.EntropyHex != tc.entropy {
			t.Errorf("entropy = %s; want %s", r.EntropyHex, tc.entropy)
		}
		if r.SeedHex != tc.seed {
			t.Errorf("seed = %s; want %s", r.SeedHex, tc.seed)
		}
	}
}

// encodeMnemonic is the test-side inverse of Decode: entropy bytes → mnemonic.
// It is deliberately independent of the decoder's internals so the round-trip
// is a real cross-check, not a tautology.
func encodeMnemonic(t *testing.T, entropy []byte) string {
	t.Helper()
	csBits := len(entropy) * 8 / 32
	digest := sha256.Sum256(entropy)

	bitAt := func(src []byte, i int) byte { return (src[i/8] >> uint(7-(i%8))) & 1 }

	total := len(entropy)*8 + csBits
	bits := make([]byte, total)
	for i := 0; i < len(entropy)*8; i++ {
		bits[i] = bitAt(entropy, i)
	}
	for i := 0; i < csBits; i++ {
		bits[len(entropy)*8+i] = bitAt(digest[:], i)
	}

	// english.txt is fetched fresh here so the encoder does not borrow the
	// package's parsed list.
	list := wordlist(t)
	var sb strings.Builder
	for w := 0; w < total/11; w++ {
		idx := 0
		for b := 0; b < 11; b++ {
			idx = idx<<1 | int(bits[w*11+b])
		}
		if w > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(list[idx])
	}
	return sb.String()
}

// TestRoundTripAllLengths encodes random-ish entropy of every BIP-39 size, then
// decodes it back — proving the index packing, the SHA-256 checksum, and all
// five lengths (128/160/192/224/256-bit) for any value, not just the anchored
// vectors.
func TestRoundTripAllLengths(t *testing.T) {
	for _, entBytes := range []int{16, 20, 24, 28, 32} {
		ent := make([]byte, entBytes)
		for i := range ent {
			ent[i] = byte((i*73 + 11) & 0xff) // deterministic spread
		}
		mn := encodeMnemonic(t, ent)
		r, err := bip39.Decode(mn, "")
		if err != nil {
			t.Fatalf("%d-byte entropy: Decode: %v", entBytes, err)
		}
		if !r.ChecksumValid {
			t.Errorf("%d-byte entropy: checksum_valid = false, want true", entBytes)
		}
		if r.EntropyBits != entBytes*8 {
			t.Errorf("%d-byte entropy: entropy_bits = %d; want %d", entBytes, r.EntropyBits, entBytes*8)
		}
		got, _ := hex.DecodeString(r.EntropyHex)
		if !bytes.Equal(got, ent) {
			t.Errorf("%d-byte entropy round-trip = %x; want %x", entBytes, got, ent)
		}
		if r.WordCount != (entBytes*8+entBytes*8/32)/11 {
			t.Errorf("%d-byte entropy: word_count = %d", entBytes, r.WordCount)
		}
	}
}

// TestBadChecksumReported confirms a typo'd phrase decodes but is flagged
// checksum-invalid rather than asserted genuine.
func TestBadChecksumReported(t *testing.T) {
	// The all-zero mnemonic ends in "about"; ending in "abandon" breaks the checksum.
	bad := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
	r, err := bip39.Decode(bad, "")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.ChecksumValid {
		t.Errorf("checksum_valid = true, want false for a typo'd phrase")
	}
	if r.Note == "" {
		t.Errorf("expected a Note flagging the invalid checksum")
	}
	if r.SeedHex == "" {
		t.Errorf("seed should still be derived for a near-miss phrase")
	}
}

// TestCaseAndWhitespaceInsensitive confirms upper-case input and extra
// whitespace decode the same as the canonical form.
func TestCaseAndWhitespaceInsensitive(t *testing.T) {
	canon := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	messy := "  ABANDON   abandon\tabandon abandon abandon abandon abandon abandon abandon abandon abandon ABOUT  "
	a, err := bip39.Decode(canon, "TREZOR")
	if err != nil {
		t.Fatal(err)
	}
	b, err := bip39.Decode(messy, "TREZOR")
	if err != nil {
		t.Fatal(err)
	}
	if a.SeedHex != b.SeedHex || a.EntropyHex != b.EntropyHex {
		t.Errorf("messy input decoded differently: seeds %s vs %s", a.SeedHex, b.SeedHex)
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":             "",
		"wrong count (11)":  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"wrong count (13)":  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
		"non-wordlist word": "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword",
	}
	for name, in := range cases {
		if _, err := bip39.Decode(in, ""); err == nil {
			t.Errorf("%s: Decode = nil error, want error", name)
		}
	}
}
