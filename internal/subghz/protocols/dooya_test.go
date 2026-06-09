// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols

import "testing"

// buildDooyaPulses emits the pulse sequence for a 40-bit Dooya code, mirroring
// the firmware encoder: a 13×te_short guard mark + 2×te_long space, then 40
// MSB-first PWM bits (1 = te_long mark + te_short space, 0 = te_short mark +
// te_long space).
func buildDooyaPulses(code uint64) []int {
	const teShort, teLong = 366, 733
	p := []int{13 * teShort, -(2 * teLong)}
	for bit := 39; bit >= 0; bit-- {
		if (code>>uint(bit))&1 == 1 {
			p = append(p, teLong, -teShort)
		} else {
			p = append(p, teShort, -teLong)
		}
	}
	p = append(p, 13*teShort) // trailing guard
	return p
}

// TestDooya_FirmwareExample decodes the worked example documented verbatim in
// the Flipper firmware (dooya.c): 0xE1DC030533 → serial 0xE1DC03, single
// channel (s/m 0), channel 5, key 0x33 = "long press down".
func TestDooya_FirmwareExample(t *testing.T) {
	res, err := Dooya{}.Decode(buildDooyaPulses(0xE1DC030533))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Protocol != "Dooya" {
		t.Errorf("protocol = %q, want Dooya", res.Protocol)
	}
	if res.Payload["serial"].(uint64) != 0xE1DC03 {
		t.Errorf("serial = 0x%X, want 0xE1DC03", res.Payload["serial"])
	}
	if res.Payload["channel_mode"].(uint64) != 0 {
		t.Errorf("channel_mode = %d, want 0 (single)", res.Payload["channel_mode"])
	}
	if res.Payload["channel"].(uint64) != 0x5 {
		t.Errorf("channel = 0x%X, want 0x5", res.Payload["channel"])
	}
	if res.Payload["key"].(uint64) != 0x33 {
		t.Errorf("key = 0x%X, want 0x33", res.Payload["key"])
	}
	if res.Payload["button"].(string) != "long press down" {
		t.Errorf("button = %q, want long press down", res.Payload["button"])
	}
	if res.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", res.Confidence)
	}
}

// TestDooya_ButtonTable checks each documented key maps to its action and
// round-trips.
func TestDooya_ButtonTable(t *testing.T) {
	cases := map[uint64]string{
		0x11: "long press up", 0x1E: "short press up", 0x33: "long press down",
		0x3C: "short press down", 0x55: "stop", 0x79: "up+down", 0x80: "up+stop",
		0x00: "unknown",
	}
	for key, want := range cases {
		code := uint64(0xE1DC03)<<16 | 0x0<<12 | 0x5<<8 | key
		res, err := Dooya{}.Decode(buildDooyaPulses(code))
		if err != nil {
			t.Fatalf("Decode(key 0x%X): %v", key, err)
		}
		if res.Payload["button"].(string) != want {
			t.Errorf("key 0x%X button = %q, want %q", key, res.Payload["button"], want)
		}
		if res.Payload["code"].(uint64) != code {
			t.Errorf("code = 0x%X, want 0x%X", res.Payload["code"], code)
		}
	}
}

// TestDooya_NoSync rejects a pulse train without the guard mark.
func TestDooya_NoSync(t *testing.T) {
	d := Dooya{}
	if _, err := d.Decode([]int{366, -733, 733, -366}); err == nil {
		t.Error("expected guard-sync error")
	}
}

// TestDooya_Truncated rejects a frame with too few bits.
func TestDooya_Truncated(t *testing.T) {
	full := buildDooyaPulses(0xE1DC030533)
	d := Dooya{}
	if _, err := d.Decode(full[:20]); err == nil {
		t.Error("expected truncation error")
	}
}
