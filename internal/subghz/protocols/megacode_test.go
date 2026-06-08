// SPDX-License-Identifier: AGPL-3.0-or-later

package protocols_test

import (
	"testing"

	"github.com/xunholy/promptzero/internal/subghz/protocols"
)

const megaTE = 1000

// megacodeGap returns the on-air inter-mark space (µs) for a (prev,cur) bit
// pair, per the Flipper firmware megacode.c encoder/decoder (cross-checked
// against both get_upload() gap widths and the feed() classifier):
//
//	(1,1)=5×TE  (1,0)=2×TE  (0,1)=8×TE  (0,0)=5×TE
func megacodeGap(prev, cur byte) int {
	switch {
	case prev == 1 && cur == 1:
		return 5000
	case prev == 1 && cur == 0:
		return 2000
	case prev == 0 && cur == 1:
		return 8000
	default: // (0,0)
		return 5000
	}
}

// buildMegacodePulses renders a 24-bit MSB-first bit slice to a MegaCode pulse
// train: a leading guard space, then a 1×TE mark per bit separated by the
// gap that encodes each transition, then a trailing reset space.
func buildMegacodePulses(bits []byte) []int {
	lead := 14000 // last bit 0 -> 14×TE; either guard width is accepted
	if bits[len(bits)-1] == 1 {
		lead = 11000
	}
	p := []int{-lead, megaTE}
	for k := 1; k < len(bits); k++ {
		p = append(p, -megacodeGap(bits[k-1], bits[k]), megaTE)
	}
	p = append(p, -12000) // trailing reset guard (≥10×TE)
	return p
}

func bitsOf(data uint32, n int) []byte {
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte((data >> uint(n-1-i)) & 1)
	}
	return b
}

// TestMegacodeFirmwareExample decodes the worked example documented verbatim in
// the Flipper firmware megacode.c: remote key 17316 (0x43A4), facility code 3,
// button 1 -> S|F|Key|Btn = 1|0011|0100001110100100|001 = 0x9A1D21.
func TestMegacodeFirmwareExample(t *testing.T) {
	const data = 0x9A1D21
	wantBits := []byte{1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1}
	got := bitsOf(data, 24)
	for i := range wantBits {
		if got[i] != wantBits[i] {
			t.Fatalf("test setup: bit %d = %d, want %d (data 0x%06X)", i, got[i], wantBits[i], data)
		}
	}

	res, err := protocols.Megacode{}.Decode(buildMegacodePulses(wantBits))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if res.Payload["code"].(uint32) != data {
		t.Errorf("code = 0x%06X, want 0x%06X", res.Payload["code"], data)
	}
	if res.Payload["serial"].(uint32) != 17316 {
		t.Errorf("serial = %d, want 17316", res.Payload["serial"])
	}
	if res.Payload["facility"].(uint32) != 3 {
		t.Errorf("facility = %d, want 3", res.Payload["facility"])
	}
	if res.Payload["button"].(uint32) != 1 {
		t.Errorf("button = %d, want 1", res.Payload["button"])
	}
	if res.Confidence != 1.0 {
		t.Errorf("confidence = %v, want 1.0", res.Confidence)
	}
}

// TestMegacodeRoundTrip renders many valid codes to pulses and confirms the
// decoder recovers the exact code and field split. Covers both guard widths and
// every (prev,cur) gap transition. The start bit (MSB) is forced to 1.
func TestMegacodeRoundTrip(t *testing.T) {
	// Deterministic spread across facility / serial / button without RNG.
	for serial := uint32(0); serial < 0x10000; serial += 1471 {
		for facility := uint32(0); facility < 16; facility += 5 {
			for button := uint32(0); button < 8; button += 3 {
				data := uint32(1)<<23 | (facility&0xF)<<19 | (serial&0xFFFF)<<3 | (button & 0x7)
				bits := bitsOf(data, 24)
				res, err := protocols.Megacode{}.Decode(buildMegacodePulses(bits))
				if err != nil {
					t.Fatalf("Decode(0x%06X): %v", data, err)
				}
				if res.Payload["code"].(uint32) != data {
					t.Fatalf("code = 0x%06X, want 0x%06X", res.Payload["code"], data)
				}
				if res.Payload["serial"].(uint32) != serial&0xFFFF {
					t.Fatalf("serial = %d, want %d", res.Payload["serial"], serial&0xFFFF)
				}
				if res.Payload["facility"].(uint32) != facility&0xF {
					t.Fatalf("facility = %d, want %d", res.Payload["facility"], facility&0xF)
				}
				if res.Payload["button"].(uint32) != button&0x7 {
					t.Fatalf("button = %d, want %d", res.Payload["button"], button&0x7)
				}
			}
		}
	}
}

func TestMegacodeRejects(t *testing.T) {
	good := buildMegacodePulses(bitsOf(0x9A1D21, 24))

	cases := map[string][]int{
		"empty":        {},
		"no header":    {1000, -2000, 1000, -5000, 1000},
		"short header": {-3000, 1000, -2000, 1000},
		"truncated":    good[:10],
	}
	for name, pulses := range cases {
		if _, err := (protocols.Megacode{}).Decode(pulses); err == nil {
			t.Errorf("%s: expected error, got nil", name)
		}
	}
}
