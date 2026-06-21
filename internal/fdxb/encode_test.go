// SPDX-License-Identifier: AGPL-3.0-or-later

package fdxb

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Encode then Decode must reproduce the inputs with a valid CRC — the strongest
// verification for an inverse generator (no external vector needed; the decoder
// is the independent oracle).
func TestEncode_RoundTrip(t *testing.T) {
	cases := []struct {
		national uint64
		country  int
		animal   bool
		dataBlk  bool
	}{
		{140000795552, 528, false, false},             // the decoder's anchor vector
		{1500030037, 999, true, false},                // the decoder's second anchor (test range)
		{0, 0, false, false},                          // minimum
		{maxNationalCode, maxCountryCode, true, true}, // maxima + both flags
		{1, 1, true, false},
		{1234567890, 250, false, true},
	}
	for _, c := range cases {
		b, err := Encode(c.national, c.country, c.animal, c.dataBlk)
		if err != nil {
			t.Fatalf("Encode(%d,%d): %v", c.national, c.country, err)
		}
		if len(b) != 10 {
			t.Fatalf("Encode(%d,%d): got %d bytes, want 10", c.national, c.country, len(b))
		}
		got, err := Decode(b)
		if err != nil {
			t.Fatalf("Decode of encoded block: %v", err)
		}
		if got.NationalCode != c.national {
			t.Errorf("national: got %d, want %d", got.NationalCode, c.national)
		}
		if got.CountryCode != c.country {
			t.Errorf("country: got %d, want %d", got.CountryCode, c.country)
		}
		if got.AnimalApplication != c.animal {
			t.Errorf("animal flag: got %v, want %v", got.AnimalApplication, c.animal)
		}
		if got.DataBlockPresent != c.dataBlk {
			t.Errorf("data-block flag: got %v, want %v", got.DataBlockPresent, c.dataBlk)
		}
		if got.CRCValid == nil || !*got.CRCValid {
			t.Errorf("CRC not valid for encoded block %X (stored %s, computed %s)", b, got.CRCStored, got.CRCComputed)
		}
	}
}

// The package doc anchors the decoder to a real tag: country 528 / national
// 140000795552 with ID block 05 D9 4D 19 04 21 00 01. The identity-bearing
// portion — the 38-bit national + 10-bit country (bytes 0..5) and the flag byte
// (byte 6) — must reproduce that real tag byte-for-byte. The real tag also
// carries a set reserved bit in byte 7 (bit 63, in the RFU range 50..63); the
// canonical encoder emits reserved bits as zero, so byte 7 is 00 here. This is
// a published-vector anchor on the identity bytes, on top of the full
// round-trip (national/country/flags/CRC) in TestEncode_RoundTrip.
func TestEncode_AnchorVector(t *testing.T) {
	b, err := Encode(140000795552, 528, false, false)
	if err != nil {
		t.Fatal(err)
	}
	// Bytes 0..6 carry national + country + flags (all non-reserved); these
	// must equal the real tag exactly.
	got := strings.ToUpper(hex.EncodeToString(b[:7]))
	const want = "05D94D19042100" // bytes 0..6 of 05D94D1904210001
	if got != want {
		t.Errorf("identity bytes = %s, want %s (the decoder's published vector, bytes 0..6)", got, want)
	}
	// Byte 7 is pure reserved; the canonical encoder zeroes it.
	if b[7] != 0x00 {
		t.Errorf("byte 7 (reserved) = 0x%02X, want 0x00 (canonical encoding zeroes reserved bits)", b[7])
	}
}

func TestEncode_Rejects(t *testing.T) {
	if _, err := Encode(maxNationalCode+1, 0, false, false); err == nil {
		t.Error("expected error for national code exceeding 38 bits")
	}
	if _, err := Encode(0, maxCountryCode+1, false, false); err == nil {
		t.Error("expected error for country code exceeding 10 bits")
	}
	if _, err := Encode(0, -1, false, false); err == nil {
		t.Error("expected error for negative country code")
	}
}
