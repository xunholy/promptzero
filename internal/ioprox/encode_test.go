// SPDX-License-Identifier: AGPL-3.0-or-later

package ioprox

import "testing"

func TestEncodeMatchesHandVector(t *testing.T) {
	// Must reproduce the independently hand-traced decode vector from v0.608:
	// FC=1, V=1, Card=1337 -> 00 78 40 60 30 59 CF 3F.
	got := Encode(1, 1, 1337)
	if got != "007840603059CF3F" {
		t.Errorf("Encode(1,1,1337) = %q, want 007840603059CF3F", got)
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := []struct {
		fc, ver byte
		card    uint16
	}{
		{1, 1, 1337},
		{101, 2, 13117},
		{255, 3, 65535},
		{0, 0, 0},
		{0x42, 0x07, 0xBEEF},
	}
	for _, c := range cases {
		hexStr := Encode(c.fc, c.ver, c.card)
		r, err := Decode(hexStr)
		if err != nil {
			t.Fatalf("Decode(Encode(%d,%d,%d)=%s): %v", c.fc, c.ver, c.card, hexStr, err)
		}
		if r.FacilityCode != int(c.fc) || r.Version != int(c.ver) || r.CardNumber != int(c.card) {
			t.Errorf("round-trip %d/%d/%d -> %d/%d/%d", c.fc, c.ver, c.card, r.FacilityCode, r.Version, r.CardNumber)
		}
		if !r.CRCValid {
			t.Errorf("encoded block for %d/%d/%d has invalid CRC", c.fc, c.ver, c.card)
		}
	}
}
