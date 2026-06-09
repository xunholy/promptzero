// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols

import "testing"

// buildIT3Pulses emits the pulse sequence for an Intertechno V3 frame, mirroring
// the firmware: a 37×te_short inter-frame gap, the start bit (mark T + space
// 10T), nbits MSB-first four-phase data bits ('1' = T,5T,T,T ; '0' = T,T,T,5T),
// then the stop bit (mark T + space 38T).
func buildIT3Pulses(code uint64, nbits int) []int {
	const teShort, teLong = 275, 1375
	p := []int{-(37 * teShort)}             // inter-frame gap
	p = append(p, teShort, -(10 * teShort)) // start bit
	for bit := nbits - 1; bit >= 0; bit-- {
		if (code>>uint(bit))&1 == 1 {
			p = append(p, teShort, -teLong, teShort, -teShort) // '1' = (T,5T,T,T)
		} else {
			p = append(p, teShort, -teShort, teShort, -teLong) // '0' = (T,T,T,5T)
		}
	}
	p = append(p, teShort, -(38 * teShort)) // stop bit
	return p
}

// TestIT3_Example32 decodes the firmware's documented 32-bit worked example
// (Key:0x3F86C59F → all_ch 0, on/off 1, ~ch 1111 so channel 0).
func TestIT3_Example32(t *testing.T) {
	res, err := IntertechnoV3{}.Decode(buildIT3Pulses(0x3F86C59F, 32))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Protocol != "Intertechno V3" {
		t.Errorf("protocol = %q", res.Protocol)
	}
	if res.Payload["code"].(uint64) != 0x3F86C59F {
		t.Errorf("code = 0x%X, want 0x3F86C59F", res.Payload["code"])
	}
	if res.Payload["bits"].(int) != 32 {
		t.Errorf("bits = %d, want 32", res.Payload["bits"])
	}
	if res.Payload["all_channels"].(bool) {
		t.Errorf("all_channels = true, want false")
	}
	if !res.Payload["on"].(bool) {
		t.Errorf("on = false, want true")
	}
	if res.Payload["channel"].(uint64) != 0 {
		t.Errorf("channel = %v, want 0", res.Payload["channel"])
	}
}

// TestIT3_Example36 decodes the firmware's documented 36-bit dimming example
// (Key:0x42D2E8856 → all_ch 0, ~ch 0101 so channel 0xA, dimm_level 0110 = 6).
func TestIT3_Example36(t *testing.T) {
	res, err := IntertechnoV3{}.Decode(buildIT3Pulses(0x42D2E8856, 36))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Payload["bits"].(int) != 36 {
		t.Fatalf("bits = %d, want 36", res.Payload["bits"])
	}
	if res.Payload["code"].(uint64) != 0x42D2E8856 {
		t.Errorf("code = 0x%X, want 0x42D2E8856", res.Payload["code"])
	}
	if res.Payload["all_channels"].(bool) {
		t.Errorf("all_channels = true, want false")
	}
	if res.Payload["channel"].(uint64) != 0xA {
		t.Errorf("channel = 0x%X, want 0xA", res.Payload["channel"])
	}
	if res.Payload["dimm_level"].(uint64) != 0x6 {
		t.Errorf("dimm_level = 0x%X, want 0x6", res.Payload["dimm_level"])
	}
}

// TestIT3_RoundTrip32 confirms build∘decode is identity across 32-bit codes.
func TestIT3_RoundTrip32(t *testing.T) {
	for _, code := range []uint64{0x00000000, 0xFFFFFFFF, 0x3F86C59F, 0x12345678, 0xAA55AA55} {
		res, err := IntertechnoV3{}.Decode(buildIT3Pulses(code, 32))
		if err != nil {
			t.Fatalf("Decode(0x%08X): %v", code, err)
		}
		if res.Payload["code"].(uint64) != code {
			t.Errorf("round-trip 0x%08X -> 0x%X", code, res.Payload["code"])
		}
		if res.Confidence != 1.0 {
			t.Errorf("0x%08X: confidence = %v, want 1.0", code, res.Confidence)
		}
	}
}

func TestIT3_NoSync(t *testing.T) {
	it := IntertechnoV3{}
	if _, err := it.Decode([]int{275, -275, 275, -1375}); err == nil {
		t.Error("expected start-sync error")
	}
}

func TestIT3_WrongBitCount(t *testing.T) {
	// 20-bit frame → neither 32 nor 36 → rejected.
	it := IntertechnoV3{}
	if _, err := it.Decode(buildIT3Pulses(0x12345, 20)); err == nil {
		t.Error("expected wrong-bit-count rejection")
	}
}
