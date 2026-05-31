// SPDX-License-Identifier: AGPL-3.0-or-later

package pacs

import (
	"strings"
	"testing"
)

// TestEncodeWiegand_RoundTrip is the primary check: a frame built by
// EncodeWiegand must decode back to the same FC/CN with parity valid, via
// the independent DecodeBits path.
func TestEncodeWiegand_RoundTrip(t *testing.T) {
	cases := []struct {
		format string
		fc, cn uint64
		want   string // substring of the decoded candidate Format
	}{
		{"H10301", 0, 1, "H10301"},
		{"H10301", 123, 4567, "H10301"},
		{"H10301", 255, 65535, "H10301"},
		{"H10306", 1, 0, "H10306"},
		{"H10306", 65535, 65535, "H10306"},
		{"H10306", 4660, 22136, "H10306"},
	}
	for _, c := range cases {
		bits, err := EncodeWiegand(c.format, c.fc, c.cn)
		if err != nil {
			t.Fatalf("EncodeWiegand(%s,%d,%d): %v", c.format, c.fc, c.cn, err)
		}
		res, err := DecodeBits(bits)
		if err != nil {
			t.Fatalf("DecodeBits(%q): %v", bits, err)
		}
		var got *Candidate
		for i := range res.Candidates {
			if strings.Contains(res.Candidates[i].Format, c.want) {
				got = &res.Candidates[i]
			}
		}
		if got == nil {
			t.Fatalf("%s fc=%d cn=%d: no %s candidate in %+v", c.format, c.fc, c.cn, c.want, res.Candidates)
		}
		if !got.ParityValid {
			t.Errorf("%s fc=%d cn=%d: round-trip parity invalid (%s)", c.format, c.fc, c.cn, bits)
		}
		if got.FacilityCode != c.fc || got.CardNumber != c.cn {
			t.Errorf("%s fc=%d cn=%d round-trips to fc=%d cn=%d", c.format, c.fc, c.cn, got.FacilityCode, got.CardNumber)
		}
	}
}

// TestEncodeWiegand_FixedVectors hand-verifies exact 26-bit frames computed
// independently from the H10301 layout (even parity over the top 12 data
// bits, odd over the bottom 12).
func TestEncodeWiegand_FixedVectors(t *testing.T) {
	vectors := []struct {
		fc, cn uint64
		want   string
	}{
		// FC=0 CN=1: data all zero except last CN bit; top12 ones=0 → Pe=0;
		// bottom12 ones=1 (odd) → Po=0.
		{0, 1, "00000000000000000000000010"},
		// FC=1 CN=0: data has one 1 in the FC byte (top half); top12 ones=1
		// → Pe=1; bottom12 ones=0 (even) → Po=1.
		{1, 0, "10000000100000000000000001"},
	}
	for _, v := range vectors {
		got, err := EncodeWiegand("H10301", v.fc, v.cn)
		if err != nil {
			t.Fatalf("EncodeWiegand(H10301,%d,%d): %v", v.fc, v.cn, err)
		}
		if got != v.want {
			t.Errorf("EncodeWiegand(H10301,%d,%d) = %q, want %q", v.fc, v.cn, got, v.want)
		}
		if len(got) != 26 {
			t.Errorf("H10301 frame length = %d, want 26", len(got))
		}
	}
}

func TestEncodeWiegand_RejectsBadInput(t *testing.T) {
	cases := []struct {
		format string
		fc, cn uint64
	}{
		{"H10301", 256, 0},   // FC > 8 bits
		{"H10301", 0, 65536}, // CN > 16 bits
		{"H10306", 65536, 0}, // FC > 16 bits
		{"NOPE", 1, 1},       // unknown format
	}
	for _, c := range cases {
		if _, err := EncodeWiegand(c.format, c.fc, c.cn); err == nil {
			t.Errorf("EncodeWiegand(%s,%d,%d): expected error, got nil", c.format, c.fc, c.cn)
		}
	}
}
