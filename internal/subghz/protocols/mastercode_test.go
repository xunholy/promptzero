// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

const (
	mcTE     = 1072
	mcTELong = 2145
)

// buildMastercodePulses renders a 36-bit Mastercode frame to a PWM pulse train:
// a ~15×te_short sync gap, then 36 MSB-first bits (bit 0 = short mark + long
// space, bit 1 = long mark + short space). The final bit's space is extended by
// the inter-frame gap, per the firmware encoder.
func buildMastercodePulses(data uint64) []int {
	p := []int{-15 * mcTE} // leading inter-frame gap
	for k := 35; k >= 0; k-- {
		bit := (data >> uint(k)) & 1
		last := k == 0
		switch {
		case bit == 1 && !last:
			p = append(p, mcTELong, -mcTE)
		case bit == 0 && !last:
			p = append(p, mcTE, -mcTELong)
		case bit == 1 && last:
			p = append(p, mcTELong, -(mcTE + 13*mcTE))
		default: // bit == 0 && last
			p = append(p, mcTE, -(mcTELong + 13*mcTE))
		}
	}
	return p
}

// TestMastercodeRoundTrip builds frames across a spread of 36-bit codes and
// confirms the decoder recovers the code and the serial/button split.
func TestMastercodeRoundTrip(t *testing.T) {
	codes := []uint64{
		0x0,
		0xFFFFFFFFF, // all ones (36 bits)
		0x123456789,
		0xABCDEF012,
		0x9A1D2_0000,
		0x55555_5555,
	}
	for _, code := range codes {
		code &= 0xFFFFFFFFF // clamp to 36 bits
		res, err := protocols.Mastercode{}.Decode(buildMastercodePulses(code))
		if err != nil {
			t.Fatalf("Decode(0x%09X): %v", code, err)
		}
		if res.Payload["code"].(uint64) != code {
			t.Errorf("code = 0x%09X, want 0x%09X", res.Payload["code"], code)
		}
		if res.Payload["serial"].(uint64) != (code>>4)&0xFFFF {
			t.Errorf("serial = 0x%X, want 0x%X", res.Payload["serial"], (code>>4)&0xFFFF)
		}
		if res.Payload["button"].(uint64) != (code>>2)&0x03 {
			t.Errorf("button = %d, want %d", res.Payload["button"], (code>>2)&0x03)
		}
		if res.Confidence != 1.0 {
			t.Errorf("confidence = %v, want 1.0", res.Confidence)
		}
	}
}

func TestMastercodeRejects(t *testing.T) {
	good := buildMastercodePulses(0x123456789)
	cases := map[string][]int{
		"empty":       {},
		"no sync gap": {mcTE, -mcTELong, mcTE, -mcTELong},
		"truncated":   good[:20],
	}
	for name, pulses := range cases {
		if _, err := (protocols.Mastercode{}).Decode(pulses); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
