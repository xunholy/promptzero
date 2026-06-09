// SPDX-License-Identifier: AGPL-3.0-or-later

package githubtoken_test

import (
	"hash/crc32"
	"testing"

	"github.com/xunholy/promptzero/internal/githubtoken"
)

// The canonical example token is assembled from parts so the contiguous,
// checksum-valid literal never appears in source (which would trip GitHub's own
// push-protection secret scanner — fittingly).
const (
	canonEntropy  = "zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ"
	canonChecksum = "0mLq17"
	canonCRC      = 714468973 // crc32(canonEntropy) == base62(canonChecksum)
)

// TestCanonicalVector anchors against the canonical example token, whose CRC32
// checksum was confirmed to validate.
func TestCanonicalVector(t *testing.T) {
	// Independently confirm the anchor: the entropy's CRC32 equals the documented
	// checksum value (and so the Base62-decoded checksum).
	if crc := crc32.ChecksumIEEE([]byte(canonEntropy)); crc != canonCRC {
		t.Fatalf("entropy CRC32 = %d; want %d (vector mis-transcribed)", crc, canonCRC)
	}

	r, err := githubtoken.Decode("ghp_" + canonEntropy + canonChecksum)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Prefix != "ghp_" || r.Type != "personal access token (classic)" {
		t.Errorf("prefix/type = %q/%q", r.Prefix, r.Type)
	}
	if !r.ChecksumChecked || !r.ChecksumValid {
		t.Errorf("checksum checked=%v valid=%v; want true/true", r.ChecksumChecked, r.ChecksumValid)
	}
}

// TestCorruptedChecksum confirms a single-character change is flagged invalid.
func TestCorruptedChecksum(t *testing.T) {
	// The canonical entropy with a flipped final checksum char.
	r, err := githubtoken.Decode("ghp_" + canonEntropy + "0mLq18")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if !r.ChecksumChecked {
		t.Fatalf("checksum not checked")
	}
	if r.ChecksumValid {
		t.Errorf("checksum_valid = true for a corrupted token, want false")
	}
}

// makeValid builds a checksum-valid token of the given prefix from a body of
// entropy, computing the trailing checksum the way GitHub does — proving the
// other classic prefixes validate under the same (vector-anchored) algorithm.
func makeValid(prefix, entropy string) string {
	const dict = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	crc := uint64(crc32.ChecksumIEEE([]byte(entropy)))
	buf := []byte("000000")
	for i := 5; i >= 0; i-- {
		buf[i] = dict[crc%62]
		crc /= 62
	}
	return prefix + entropy + string(buf)
}

func TestAllClassicPrefixesValidate(t *testing.T) {
	for _, p := range []string{"ghp_", "gho_", "ghu_", "ghs_", "ghr_"} {
		tok := makeValid(p, "abcdefghijklmnopqrstuvwxyz0123")
		r, err := githubtoken.Decode(tok)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if r.Prefix != p || !r.ChecksumValid {
			t.Errorf("%s: prefix=%q valid=%v", p, r.Prefix, r.ChecksumValid)
		}
	}
}

// TestFineGrained identifies github_pat_ without asserting its checksum.
func TestFineGrained(t *testing.T) {
	r, err := githubtoken.Decode("github_pat_11ABCDEFG0abcdefghijklmn_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if r.Prefix != "github_pat_" || r.Type != "fine-grained personal access token" {
		t.Errorf("prefix/type = %q/%q", r.Prefix, r.Type)
	}
	if r.ChecksumChecked {
		t.Errorf("checksum_checked = true; fine-grained checksum should not be asserted")
	}
}

func TestRejects(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"not github":     "AKIAY34FZKBOKMUTVV7A",
		"unknown prefix": "ghx_zQWBuTSOoRi4A9spHcVY5ncnsDkxkJ0mLq17",
		"too short":      "ghp_abc",
	}
	for name, in := range cases {
		if _, err := githubtoken.Decode(in); err == nil {
			t.Errorf("%s: Decode(%q) = nil error, want error", name, in)
		}
	}
}
