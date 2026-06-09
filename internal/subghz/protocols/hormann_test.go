// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols

import "testing"

// buildHormannPulses emits the pulse sequence for a 44-bit Hormann HSM code,
// mirroring the firmware encoder: a 24×te_short guard mark + te_short space,
// then 44 MSB-first PWM bits (1 = te_long mark + te_short space, 0 = te_short
// mark + te_long space).
func buildHormannPulses(code uint64) []int {
	const teShort, teLong = 500, 1000
	p := []int{24 * teShort, -teShort}
	for bit := 43; bit >= 0; bit-- {
		if (code>>uint(bit))&1 == 1 {
			p = append(p, teLong, -teShort)
		} else {
			p = append(p, teShort, -teLong)
		}
	}
	p = append(p, 24*teShort) // trailing guard
	return p
}

func TestHormann_Decode(t *testing.T) {
	// 0xFFABCDEF703 satisfies the fixed pattern (top byte 0xFF, bottom 0x3);
	// button = (code >> 8) & 0xF = 0x7.
	const code = 0xFFABCDEF703
	res, err := Hormann{}.Decode(buildHormannPulses(code))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Protocol != "Hormann HSM" {
		t.Errorf("protocol = %q, want Hormann HSM", res.Protocol)
	}
	if res.Payload["code"].(uint64) != code {
		t.Errorf("code = 0x%X, want 0x%X", res.Payload["code"], uint64(code))
	}
	if res.Payload["button"].(uint64) != 0x7 {
		t.Errorf("button = 0x%X, want 0x7", res.Payload["button"])
	}
	if res.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", res.Confidence)
	}
}

// TestHormann_RoundTrip across several pattern-valid codes / buttons.
func TestHormann_RoundTrip(t *testing.T) {
	cases := []struct {
		code uint64
		btn  uint64
	}{
		{0xFF000000003, 0x0},
		{0xFF000000103, 0x1},
		{0xFFFFFFFFF03 | hormannPattern, 0xF},
		{0xFF0A5A5A703, 0x7},
		{0xFF012345603 | hormannPattern, (0xFF012345603 >> 8) & 0xF},
	}
	for _, c := range cases {
		code := c.code | hormannPattern // ensure the fixed bits are set
		res, err := Hormann{}.Decode(buildHormannPulses(code))
		if err != nil {
			t.Fatalf("Decode(0x%X): %v", code, err)
		}
		if res.Payload["code"].(uint64) != code {
			t.Errorf("code = 0x%X, want 0x%X", res.Payload["code"], code)
		}
		if got := res.Payload["button"].(uint64); got != (code>>8)&0xF {
			t.Errorf("button = 0x%X, want 0x%X", got, (code>>8)&0xF)
		}
	}
}

// TestHormann_PatternGate rejects a 44-bit frame that does not carry the fixed
// HORMANN_HSM_PATTERN bits — it must not be mis-identified as Hormann.
func TestHormann_PatternGate(t *testing.T) {
	// Clear the top byte so the pattern check fails.
	const bad = 0x00ABCDEF703
	h := Hormann{}
	if _, err := h.Decode(buildHormannPulses(bad)); err == nil {
		t.Error("expected rejection of a frame missing the fixed pattern bits")
	}
}

// TestHormann_NoSync rejects a pulse train with no guard mark.
func TestHormann_NoSync(t *testing.T) {
	h := Hormann{}
	if _, err := h.Decode([]int{500, -1000, 1000, -500}); err == nil {
		t.Error("expected guard-sync error")
	}
}
