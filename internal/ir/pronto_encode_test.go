// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"strings"
	"testing"
)

func TestEncodeProntoCarrierAnchor(t *testing.T) {
	// 38 kHz -> frequency word 0x006D (canonical); 9000/4500µs leader -> 0156/00AB.
	code, err := EncodePronto("9000 4500", 38000)
	if err != nil {
		t.Fatalf("EncodePronto: %v", err)
	}
	words := strings.Fields(code)
	if words[0] != "0000" || words[1] != "006D" {
		t.Errorf("header = %v, want 0000 006D", words[:2])
	}
	if words[2] != "0001" || words[3] != "0000" {
		t.Errorf("counts = %v, want 0001 0000", words[2:4])
	}
	if words[4] != "0156" || words[5] != "00AB" {
		t.Errorf("leader bursts = %v, want 0156 00AB", words[4:6])
	}
}

func TestProntoRoundTrip(t *testing.T) {
	// encode(timings) -> decode -> timings reproduced within carrier-period rounding.
	orig := []int{9000, 4500, 560, 560, 560, 1690, 560, 560, 560, 40000}
	in := joinInts(orig)
	code, err := EncodePronto(in, 38000)
	if err != nil {
		t.Fatalf("EncodePronto: %v", err)
	}
	dec, err := DecodePronto(code)
	if err != nil {
		t.Fatalf("DecodePronto: %v", err)
	}
	if len(dec.IntroTimings) != len(orig) {
		t.Fatalf("round-trip length %d, want %d", len(dec.IntroTimings), len(orig))
	}
	period := float64(0x6D) * prontoClockUS
	for i := range orig {
		diff := dec.IntroTimings[i] - orig[i]
		if diff < 0 {
			diff = -diff
		}
		// within one carrier period (rounding granularity)
		if float64(diff) > period+1 {
			t.Errorf("timing[%d] = %d, want ~%d (diff %d > period %.0f)", i, dec.IntroTimings[i], orig[i], diff, period)
		}
	}
	if dec.CarrierHz < 37000 || dec.CarrierHz > 39000 {
		t.Errorf("carrier = %d, want ~38000", dec.CarrierHz)
	}
}

func TestEncodeProntoErrors(t *testing.T) {
	cases := []struct {
		timings string
		hz      int
	}{
		{"", 38000},
		{"9000", 38000},          // odd count
		{"9000 4500 560", 38000}, // odd count
		{"9000 4500", 0},         // bad carrier
		{"9000 4500", -5},
		{"abc def", 38000}, // non-numeric
	}
	for _, c := range cases {
		if _, err := EncodePronto(c.timings, c.hz); err == nil {
			t.Errorf("EncodePronto(%q,%d) expected error", c.timings, c.hz)
		}
	}
}
