// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols

import "testing"

// buildMarantec24Pulses emits the pulse sequence for a 24-bit Marantec24 code,
// mirroring the firmware: a 9×te_long inter-frame gap, then 24 MSB-first bits
// (0 = te_long mark + 3×te_short space, 1 = te_short mark + 2×te_long space),
// then a closing gap.
func buildMarantec24Pulses(code uint64) []int {
	const teShort, teLong = 800, 1600
	p := []int{-(9 * teLong)}
	for bit := 23; bit >= 0; bit-- {
		if (code>>uint(bit))&1 == 1 {
			p = append(p, teShort, -(2 * teLong)) // bit 1
		} else {
			p = append(p, teLong, -(3 * teShort)) // bit 0
		}
	}
	p = append(p, -(9 * teLong)) // closing gap
	return p
}

func TestMarantec24_RoundTrip(t *testing.T) {
	cases := []struct {
		code   uint64
		serial uint64
		btn    uint64
	}{
		{0x000000, 0x00000, 0x0},
		{0xABCDE5, 0xABCDE, 0x5},
		{0xFFFFFF, 0xFFFFF, 0xF},
		{0x123457, 0x12345, 0x7},
		{0x000011, 0x00001, 0x1},
	}
	for _, c := range cases {
		res, err := Marantec24{}.Decode(buildMarantec24Pulses(c.code))
		if err != nil {
			t.Fatalf("Decode(0x%06X): %v", c.code, err)
		}
		if res.Protocol != "Marantec24" {
			t.Errorf("protocol = %q, want Marantec24", res.Protocol)
		}
		if res.Payload["code"].(uint64) != c.code {
			t.Errorf("code = 0x%06X, want 0x%06X", res.Payload["code"], c.code)
		}
		if res.Payload["serial"].(uint64) != c.serial {
			t.Errorf("serial = 0x%05X, want 0x%05X", res.Payload["serial"], c.serial)
		}
		if res.Payload["button"].(uint64) != c.btn {
			t.Errorf("button = 0x%X, want 0x%X", res.Payload["button"], c.btn)
		}
		if res.Bits != nil && len(res.Bits) != 24 {
			t.Errorf("bits = %d, want 24", len(res.Bits))
		}
	}
}

func TestMarantec24_NoSync(t *testing.T) {
	m := Marantec24{}
	if _, err := m.Decode([]int{800, -2400, 1600, -2400}); err == nil {
		t.Error("expected inter-frame-gap sync error")
	}
}

func TestMarantec24_Truncated(t *testing.T) {
	full := buildMarantec24Pulses(0xABCDE5)
	m := Marantec24{}
	if _, err := m.Decode(full[:10]); err == nil {
		t.Error("expected truncation error")
	}
}
