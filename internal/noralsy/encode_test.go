// SPDX-License-Identifier: AGPL-3.0-or-later

package noralsy

import "testing"

func TestEncodeMatchesDecodeVector(t *testing.T) {
	// Must reproduce the v0.611 decode vector: card 1234567, year 2021 ->
	// bb0214ff1232104567370000.
	got, err := Encode(1234567, 2021)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != "BB0214FF1232104567370000" {
		t.Errorf("Encode(1234567,2021) = %q, want BB0214FF1232104567370000", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		card uint64
		year int
	}{
		{1234567, 2021},
		{0, 2000},
		{9999999, 2060},
		{1, 1999},
		{4242424, 2024},
	}
	for _, c := range cases {
		hexStr, err := Encode(c.card, c.year)
		if err != nil {
			t.Fatalf("Encode(%d,%d): %v", c.card, c.year, err)
		}
		r, err := Decode(hexStr)
		if err != nil {
			t.Fatalf("Decode(Encode(%d,%d)=%s): %v", c.card, c.year, hexStr, err)
		}
		if !r.CardIDIsBCD || r.CardIDBCD != c.card {
			t.Errorf("round-trip card %d -> %d (isBCD=%v)", c.card, r.CardIDBCD, r.CardIDIsBCD)
		}
		if r.Year != c.year {
			t.Errorf("round-trip year %d -> %d", c.year, r.Year)
		}
		if !r.Chk1Valid || !r.Chk2Valid {
			t.Errorf("encoded block for %d/%d has invalid checksum(s)", c.card, c.year)
		}
	}
}

func TestEncodeErrors(t *testing.T) {
	if _, err := Encode(10_000_000, 2021); err == nil {
		t.Errorf("expected range error for an 8-digit card")
	}
	if _, err := Encode(1234, 1950); err == nil {
		t.Errorf("expected year-range error for 1950")
	}
	if _, err := Encode(1234, 2061); err == nil {
		t.Errorf("expected year-range error for 2061")
	}
}
