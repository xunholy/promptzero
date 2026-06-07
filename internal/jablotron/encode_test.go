// SPDX-License-Identifier: AGPL-3.0-or-later

package jablotron

import "testing"

func TestEncodeMatchesDecodeVector(t *testing.T) {
	// Must reproduce the v0.609 decode vector: card 1234567890 -> ffff12345678909e.
	got, err := Encode(1234567890)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if got != "FFFF12345678909E" {
		t.Errorf("Encode(1234567890) = %q, want FFFF12345678909E", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, n := range []uint64{0, 1, 1234567890, 9999999999, 42, 100, 9090909090} {
		hexStr, err := Encode(n)
		if err != nil {
			t.Fatalf("Encode(%d): %v", n, err)
		}
		r, err := Decode(hexStr)
		if err != nil {
			t.Fatalf("Decode(Encode(%d)=%s): %v", n, hexStr, err)
		}
		if r.CardID != n {
			t.Errorf("round-trip %d -> %d", n, r.CardID)
		}
		if !r.CardIDIsBCD {
			t.Errorf("encoded card %d should be BCD-valid", n)
		}
		if !r.CRCValid {
			t.Errorf("encoded block for %d has invalid checksum", n)
		}
	}
}

func TestEncodeRangeError(t *testing.T) {
	if _, err := Encode(10_000_000_000); err == nil {
		t.Errorf("expected range error for an 11-digit card number")
	}
}
