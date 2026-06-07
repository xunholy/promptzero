// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

// encodeGateTXFrame builds a Gate TX pulse stream: a long header space (47×TE),
// a te_long start-bit mark, then 24 MSB-first bits where bit 0 = short space +
// long mark and bit 1 = long space + short mark. Marks are +, spaces are −.
func encodeGateTXFrame(code uint32, teShort, teLong int) []int {
	p := []int{-teShort * 47, teLong} // header space + start-bit mark
	for i := 23; i >= 0; i-- {
		if (code>>uint(i))&1 == 1 {
			p = append(p, -teLong, teShort) // bit 1
		} else {
			p = append(p, -teShort, teLong) // bit 0
		}
	}
	p = append(p, -teShort*47) // trailing inter-frame gap
	return p
}

func TestGateTXRoundTrip(t *testing.T) {
	cases := []struct {
		code   uint32
		serial uint32
		button uint32
	}{
		{0x123456, 295622, 10}, // verified against the Flipper reversed-key formula
		{0xABCDEF, 875327, 7},
		{0xFFFFFF, 1048575, 15},
	}
	for _, c := range cases {
		pulses := encodeGateTXFrame(c.code, 350, 700)
		res, err := protocols.GateTX{}.Decode(pulses)
		if err != nil {
			t.Fatalf("Decode(0x%06X): %v", c.code, err)
		}
		if res.Confidence < 0.99 {
			t.Errorf("0x%06X: confidence %.2f, want ~1.0", c.code, res.Confidence)
		}
		if got := res.Payload["code"].(uint32); got != c.code {
			t.Errorf("code = 0x%06X, want 0x%06X", got, c.code)
		}
		if got := res.Payload["serial"].(uint32); got != c.serial {
			t.Errorf("0x%06X: serial = %d, want %d", c.code, got, c.serial)
		}
		if got := res.Payload["button"].(uint32); got != c.button {
			t.Errorf("0x%06X: button = %d, want %d", c.code, got, c.button)
		}
	}
}

func TestGateTXName(t *testing.T) {
	if (protocols.GateTX{}).Name() != "Gate TX" {
		t.Errorf("Name() = %q", protocols.GateTX{}.Name())
	}
}

func TestGateTXNoSync(t *testing.T) {
	pulses := make([]int, 40)
	for i := range pulses {
		if i%2 == 0 {
			pulses[i] = 350
		} else {
			pulses[i] = -350
		}
	}
	if _, err := (protocols.GateTX{}).Decode(pulses); err == nil {
		t.Error("expected error when no sync")
	}
}
