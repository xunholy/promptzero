// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"fmt"
	"strings"
	"testing"
)

// The two literal timing arrays below are derived BY HAND from the published
// Philips RC5 specification (14 bits MSB-first: S1 S2 toggle, 5 address, 6
// command; Manchester where 1 = 889µs space then 889µs mark, 0 = mark then
// space; a capture starts at the first mark, so S1's leading space is not
// recorded). They are independent of the Go encoder (genRC5) and so anchor the
// decoder against the spec, not merely against its own inverse.

// rc5Zero is address 0, command 0, toggle 0: bits 1 1 0 00000 000000.
// Half-bits (dropping S1's leading space): on | off | on,on | then 23
// alternating half-bits -> 889 889 1778 then 23×889.
const rc5Zero = "889 889 1778 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889 889"

// rc5A1C32 is address 1 (A0=1), command 32 (C5=1), toggle 0:
// bits 1 1 0 00001 100000. Hand-traced to merged durations with 1778µs marks
// where two on/on half-bits meet (the S2->T boundary, the A0->C5 boundary, and
// the C5 1-bit) — positions 3, 12 and 15.
const rc5A1C32 = "889 889 1778 889 889 889 889 889 889 889 889 1778 889 889 1778 889 889 889 889 889 889 889 889"

func TestDecodeRC5Zero(t *testing.T) {
	r, err := DecodeRaw(rc5Zero)
	if err != nil {
		t.Fatalf("DecodeRaw: %v", err)
	}
	if r.Protocol != "RC5" {
		t.Fatalf("protocol = %q, want RC5", r.Protocol)
	}
	if r.Address != 0 || r.Command != 0 {
		t.Errorf("addr/cmd = %d/%d, want 0/0", r.Address, r.Command)
	}
	if r.Bits != 14 {
		t.Errorf("bits = %d, want 14", r.Bits)
	}
}

func TestDecodeRC5AddressCommand(t *testing.T) {
	// Independent hand-traced anchor for the address/command bit positions.
	r, err := DecodeRaw(rc5A1C32)
	if err != nil {
		t.Fatalf("DecodeRaw: %v", err)
	}
	if r.Protocol != "RC5" {
		t.Fatalf("protocol = %q", r.Protocol)
	}
	if r.Address != 1 {
		t.Errorf("address = %d, want 1", r.Address)
	}
	if r.Command != 32 {
		t.Errorf("command = %d, want 32", r.Command)
	}
}

func TestDecodeRC5RoundTrip(t *testing.T) {
	for _, tc := range []struct{ addr, cmd, tog int }{
		{0, 0, 0}, {1, 32, 0}, {20, 1, 1}, {31, 63, 0}, {5, 35, 1},
		{0, 64, 0},   // RC5X command bit 6 -> S2=0
		{31, 127, 1}, // RC5X max
		{10, 0, 0}, {0, 13, 1}, {16, 48, 0},
	} {
		s := genRC5(tc.addr, tc.cmd, tc.tog)
		r, err := DecodeRaw(s)
		if err != nil {
			t.Errorf("decode(%d,%d,%d): %v", tc.addr, tc.cmd, tc.tog, err)
			continue
		}
		if r.Address != tc.addr || r.Command != tc.cmd {
			t.Errorf("round-trip (%d,%d,%d) -> addr=%d cmd=%d", tc.addr, tc.cmd, tc.tog, r.Address, r.Command)
		}
		wantProto := "RC5"
		if tc.cmd >= 64 {
			wantProto = "RC5X"
		}
		if r.Protocol != wantProto {
			t.Errorf("(%d,%d) protocol = %q, want %q", tc.addr, tc.cmd, r.Protocol, wantProto)
		}
	}
}

func TestDecodeRC5RejectsNonRC5(t *testing.T) {
	// All marks/spaces ~889 but a count that can't form 28 half-bits with a
	// valid S1 — must reject, not mis-decode.
	if _, err := DecodeRaw("889 889 889"); err == nil {
		t.Error("expected rejection of too-short RC5 train")
	}
	// A duration that is neither a half nor full bit.
	if _, err := DecodeRaw("889 889 3000 889"); err == nil {
		t.Error("expected rejection of out-of-grid duration")
	}
}

// genRC5 builds a realistic RC5 capture (microsecond timings starting at the
// first mark) for an address (0-31) + command (0-127) + toggle. command bit 6
// drives the RC5X S2 inversion. Independent of the decoder.
func genRC5(address, command, toggle int) string {
	s2 := 1 - ((command >> 6) & 1)
	six := command & 0x3F
	bits := []int{1, s2, toggle}
	for i := 4; i >= 0; i-- {
		bits = append(bits, (address>>i)&1)
	}
	for i := 5; i >= 0; i-- {
		bits = append(bits, (six>>i)&1)
	}
	// Expand to half-bit levels: 1 -> off,on ; 0 -> on,off.
	var half []bool
	for _, b := range bits {
		if b == 1 {
			half = append(half, false, true)
		} else {
			half = append(half, true, false)
		}
	}
	half = half[1:] // drop S1's leading off (capture starts at first mark)
	// Merge consecutive equal levels into 889 / 1778 durations.
	var out []string
	for i := 0; i < len(half); {
		j := i
		for j < len(half) && half[j] == half[i] {
			j++
		}
		out = append(out, fmt.Sprintf("%d", (j-i)*rc5HalfBit))
		i = j
	}
	return strings.Join(out, " ")
}
