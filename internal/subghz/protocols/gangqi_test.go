// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

const (
	gqShort = 500
	gqLong  = 1200
	gqDelta = 200
)

// buildGangQiPulses renders a 34-bit GangQi frame to a PWM pulse train: a
// 2×te_long leading inter-frame gap, then 34 MSB-first bits (bit 0 = short mark
// + long space, bit 1 = long mark + short space). The final bit's trailing
// space is the closing gap (te_short×4 + te_delta), per the firmware encoder.
func buildGangQiPulses(data uint64) []int {
	const closingGap = gqShort*4 + gqDelta // 2200 µs, within the 2×te_long window
	p := []int{-(2 * gqLong)}              // leading inter-frame gap
	for k := 33; k >= 0; k-- {
		bit := (data >> uint(k)) & 1
		last := k == 0
		space := -gqLong
		mark := gqShort
		if bit == 1 {
			mark, space = gqLong, -gqShort
		}
		if last {
			space = -closingGap
		}
		p = append(p, mark, space)
	}
	return p
}

// makeGangQiCode assembles a 34-bit GangQi code from a 20-bit upper field and a
// 4-bit button, computing the original-remote bytesum exactly as the firmware
// encoder does so the frame passes the checksum gate (checksum_ok == true).
func makeGangQiCode(upper20 uint64, btn byte) uint64 {
	upper20 &= 0xFFFFF
	btn &= 0xF
	serial16 := uint16(upper20 >> 4) // = (data >> 18) & 0xFFFF
	constAndBtn := byte(0xD0 | btn)
	bytesum := byte(0xC8) - byte(serial16>>8) - byte(serial16&0xFF) - constAndBtn
	return upper20<<14 | uint64(btn)<<10 | uint64(bytesum)<<2
}

// TestGangQiRoundTrip builds checksum-valid frames across a spread of codes and
// confirms the decoder recovers the code, serial, button and a passing checksum.
func TestGangQiRoundTrip(t *testing.T) {
	cases := []struct {
		upper20 uint64
		btn     byte
	}{
		{0x00000, 0x0},
		{0xFFFFF, 0xF},
		{0x12345, 0xD}, // Arm
		{0xABCDE, 0xE}, // Disarm
		{0x9A1D2, 0x7}, // Ring
		{0x55555, 0xB}, // Alarm
	}
	for _, tc := range cases {
		code := makeGangQiCode(tc.upper20, tc.btn)
		res, err := protocols.GangQi{}.Decode(buildGangQiPulses(code))
		if err != nil {
			t.Fatalf("Decode(0x%09X): %v", code, err)
		}
		if got := res.Payload["code"].(uint64); got != code {
			t.Errorf("code = 0x%09X, want 0x%09X", got, code)
		}
		if got := res.Payload["serial"].(uint64); got != (code>>16)&0xFFFFF {
			t.Errorf("serial = 0x%X, want 0x%X", got, (code>>16)&0xFFFFF)
		}
		if got := res.Payload["button"].(byte); got != tc.btn {
			t.Errorf("button = 0x%X, want 0x%X", got, tc.btn)
		}
		if ok := res.Payload["checksum_ok"].(bool); !ok {
			t.Errorf("code 0x%09X: checksum_ok = false, want true", code)
		}
		if res.Confidence != 1.0 {
			t.Errorf("code 0x%09X: confidence = %v, want 1.0", code, res.Confidence)
		}
	}
}

// TestGangQiBadChecksumDecodesHalfConfidence confirms a structurally valid frame
// with a corrupted bytesum still decodes but is flagged and confidence-halved,
// so a checksum-valid match always outranks it.
func TestGangQiBadChecksumDecodesHalfConfidence(t *testing.T) {
	code := makeGangQiCode(0x12345, 0xD)
	code ^= 0x4 // flip a bytesum-field bit (bits[9:2]) — breaks both sums
	res, err := protocols.GangQi{}.Decode(buildGangQiPulses(code))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Payload["checksum_ok"].(bool) {
		t.Errorf("checksum_ok = true, want false")
	}
	if res.Confidence != 0.5 {
		t.Errorf("confidence = %v, want 0.5", res.Confidence)
	}
}

func TestGangQiRejects(t *testing.T) {
	good := buildGangQiPulses(makeGangQiCode(0x12345, 0xD))
	cases := map[string][]int{
		"empty":       {},
		"no sync gap": {gqShort, -gqLong, gqLong, -gqShort},
		"truncated":   good[:20],
	}
	for name, pulses := range cases {
		if _, err := (protocols.GangQi{}).Decode(pulses); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
