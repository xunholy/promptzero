// SPDX-License-Identifier: AGPL-3.0-or-later

package presco

import "testing"

func TestEncodeMatchesDecodeVector(t *testing.T) {
	// Must reproduce the v0.612 decode vector: full code 0x07AABBCC.
	if got := Encode(0x07AABBCC); got != "10D00000000000000000000007AABBCC" {
		t.Errorf("Encode(0x07AABBCC) = %q, want 10D00000000000000000000007AABBCC", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	for _, full := range []uint32{0, 1, 0x07AABBCC, 0x12345678, 0xFFFFFFFF} {
		hexStr := Encode(full)
		r, err := Decode(hexStr)
		if err != nil {
			t.Fatalf("Decode(Encode(0x%08X)=%s): %v", full, hexStr, err)
		}
		if r.FullCode != full {
			t.Errorf("round-trip 0x%08X -> 0x%08X", full, r.FullCode)
		}
		// site/user are the documented sub-fields of the full code.
		if r.SiteCode != int((full>>24)&0xFF) || r.UserCode != int(full&0xFFFF) {
			t.Errorf("site/user mismatch for 0x%08X: %d/%d", full, r.SiteCode, r.UserCode)
		}
	}
}
