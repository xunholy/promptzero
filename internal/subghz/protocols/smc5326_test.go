// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

// encodeSMC5326Frame builds an SMC5326 pulse stream: a long inter-frame gap
// space (24×TE) then 25 MSB-first mark-first bits — bit 0 = short mark + long
// space, bit 1 = long mark + short space (te_long = 3×te_short).
func encodeSMC5326Frame(code uint32, te int) []int {
	p := []int{-te * 24}
	for i := 24; i >= 0; i-- {
		if (code>>uint(i))&1 == 1 {
			p = append(p, te*3, -te) // bit 1
		} else {
			p = append(p, te, -te*3) // bit 0
		}
	}
	p = append(p, te, -te*24) // guard mark + trailing gap
	return p
}

func TestSMC5326RoundTrip(t *testing.T) {
	cases := []struct {
		code uint32
		addr uint32
	}{
		{0x0123456, 0x091A},
		{0x1FFFFFF, 0xFFFF},
		{0x0000001, 0x0000},
		{0x1AAAAAA, 0xD555},
	}
	for _, c := range cases {
		pulses := encodeSMC5326Frame(c.code, 300)
		res, err := protocols.SMC5326{}.Decode(pulses)
		if err != nil {
			t.Fatalf("Decode(0x%07X): %v", c.code, err)
		}
		if res.Confidence < 0.99 {
			t.Errorf("0x%07X: confidence %.2f", c.code, res.Confidence)
		}
		if got := res.Payload["code"].(uint32); got != c.code {
			t.Errorf("code = 0x%07X, want 0x%07X", got, c.code)
		}
		if got := res.Payload["address"].(uint32); got != c.addr {
			t.Errorf("0x%07X: address = 0x%04X, want 0x%04X", c.code, got, c.addr)
		}
	}
}

func TestSMC5326Name(t *testing.T) {
	if (protocols.SMC5326{}).Name() != "SMC5326" {
		t.Errorf("Name() = %q", protocols.SMC5326{}.Name())
	}
}

func TestSMC5326NoSync(t *testing.T) {
	pulses := make([]int, 40)
	for i := range pulses {
		if i%2 == 0 {
			pulses[i] = 300
		} else {
			pulses[i] = -300
		}
	}
	if _, err := (protocols.SMC5326{}).Decode(pulses); err == nil {
		t.Error("expected error when no sync")
	}
}
