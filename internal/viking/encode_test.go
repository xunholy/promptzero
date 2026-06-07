// SPDX-License-Identifier: AGPL-3.0-or-later

package viking

import "testing"

func TestEncodeMatchesDecodeVector(t *testing.T) {
	// Must reproduce the v0.610 decode vector: card 0x0001A337 -> F200000001A337CF.
	if got := Encode(0x0001A337); got != "F200000001A337CF" {
		t.Errorf("Encode(0x0001A337) = %q, want F200000001A337CF", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, id := range []uint32{0, 1, 0x0001A337, 0x12345678, 0xFFFFFFFF, 0xDEADBEEF} {
		hexStr := Encode(id)
		r, err := Decode(hexStr)
		if err != nil {
			t.Fatalf("Decode(Encode(0x%08X)=%s): %v", id, hexStr, err)
		}
		if r.CardID != id {
			t.Errorf("round-trip 0x%08X -> 0x%08X", id, r.CardID)
		}
		if !r.CRCValid {
			t.Errorf("encoded block for 0x%08X has invalid checksum", id)
		}
	}
}
