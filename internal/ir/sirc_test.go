// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"strconv"
	"strings"
	"testing"
)

// genSIRC builds a Sony SIRC raw timing train: 7 command bits then the address
// bits (5 for 12-bit, 8 for 15-bit, 5 + 8 extended for 20-bit), all LSB-first.
// Test-only encoder — the round-trip anchor for the decoder.
func genSIRC(command, address, ext, nbits int) string {
	cmdBits := 7
	var addrBits, extBits int
	switch nbits {
	case 12:
		addrBits, extBits = 5, 0
	case 15:
		addrBits, extBits = 8, 0
	case 20:
		addrBits, extBits = 5, 8
	}
	var bits []int
	for i := 0; i < cmdBits; i++ {
		bits = append(bits, (command>>i)&1)
	}
	for i := 0; i < addrBits; i++ {
		bits = append(bits, (address>>i)&1)
	}
	for i := 0; i < extBits; i++ {
		bits = append(bits, (ext>>i)&1)
	}
	t := []int{sircLeaderMark, sircLeaderSpace}
	for _, b := range bits {
		if b == 1 {
			t = append(t, sircOneMark)
		} else {
			t = append(t, sircZeroMark)
		}
		t = append(t, sircBitSpace)
	}
	return join(t)
}

func TestDecodeSIRC_RoundTrip12(t *testing.T) {
	cases := []struct{ cmd, addr int }{
		{0x00, 0x00}, {0x01, 0x01}, {0x12, 0x05}, {0x7F, 0x1F}, {0x15, 0x10},
	}
	for _, c := range cases {
		r, err := DecodeRaw(genSIRC(c.cmd, c.addr, 0, 12))
		if err != nil {
			t.Fatalf("cmd=%02X addr=%02X: %v", c.cmd, c.addr, err)
		}
		if r.Protocol != "Sony SIRC (12-bit)" {
			t.Errorf("protocol = %s, want Sony SIRC (12-bit)", r.Protocol)
		}
		if r.Command != c.cmd || r.Address != c.addr {
			t.Errorf("cmd/addr = %02X/%02X, want %02X/%02X", r.Command, r.Address, c.cmd, c.addr)
		}
		if r.Bits != 12 {
			t.Errorf("bits = %d, want 12", r.Bits)
		}
	}
}

// TestDecodeSIRC_HandVector: command 1, address 1, 12-bit. Command bits
// LSB-first = 1,0,0,0,0,0,0; address = 1,0,0,0,0. Independent of genSIRC's
// field assembly logic for the leading bits.
func TestDecodeSIRC_HandVector(t *testing.T) {
	// leader + cmd bit0=1 (1200) + 6 zeros (600) + addr bit0=1 (1200) + 4 zeros.
	parts := []int{2400, 600, 1200, 600}
	for i := 0; i < 6; i++ {
		parts = append(parts, 600, 600)
	}
	parts = append(parts, 1200, 600) // address LSB = 1
	for i := 0; i < 4; i++ {
		parts = append(parts, 600, 600)
	}
	r, err := DecodeRaw(join(parts))
	if err != nil {
		t.Fatal(err)
	}
	if r.Command != 1 || r.Address != 1 || r.Bits != 12 {
		t.Errorf("got cmd=%d addr=%d bits=%d, want 1/1/12", r.Command, r.Address, r.Bits)
	}
}

func TestDecodeSIRC_15bit(t *testing.T) {
	r, err := DecodeRaw(genSIRC(0x2A, 0x90, 0, 15))
	if err != nil {
		t.Fatal(err)
	}
	if r.Protocol != "Sony SIRC (15-bit)" || r.Command != 0x2A || r.Address != 0x90 {
		t.Errorf("got %s cmd=%02X addr=%02X, want 15-bit 2A/90", r.Protocol, r.Command, r.Address)
	}
}

func TestDecodeSIRC_20bit(t *testing.T) {
	r, err := DecodeRaw(genSIRC(0x11, 0x09, 0xAB, 20))
	if err != nil {
		t.Fatal(err)
	}
	if r.Protocol != "Sony SIRC (20-bit)" || r.Command != 0x11 || r.Address != 0x09 || r.Bits != 20 {
		t.Errorf("got %s cmd=%02X addr=%02X bits=%d", r.Protocol, r.Command, r.Address, r.Bits)
	}
	// Extended byte surfaced in a note.
	joined := strings.Join(r.Notes, " ")
	if !strings.Contains(joined, "0xAB") {
		t.Errorf("expected extended byte 0xAB in notes, got %q", joined)
	}
}

func TestDecodeSIRC_Tolerance(t *testing.T) {
	raw := genSIRC(0x12, 0x05, 0, 12)
	parts := strings.Fields(raw)
	scaled := make([]string, len(parts))
	for i, p := range parts {
		n, _ := strconv.Atoi(p)
		scaled[i] = strconv.Itoa(n * 115 / 100) // +15% drift
	}
	r, err := DecodeRaw(strings.Join(scaled, " "))
	if err != nil {
		t.Fatalf("scaled SIRC should still decode: %v", err)
	}
	if r.Command != 0x12 || r.Address != 0x05 {
		t.Errorf("scaled decode cmd/addr = %02X/%02X, want 12/05", r.Command, r.Address)
	}
}

func TestDecodeSIRC_Errors(t *testing.T) {
	bad := []string{
		"2400 8000 1200 600",        // leader space not ~600
		"2400 600 1200 600 600 600", // 2 bits — not 12/15/20
		"2400 600 3000 600",         // bit mark out of range
		buildSIRCBits(13),           // 13 bits — invalid count
		buildSIRCBits(11),           // 11 bits — invalid count
	}
	for i, s := range bad {
		if _, err := DecodeRaw(s); err == nil {
			t.Errorf("case %d (%q): expected error", i, s)
		}
	}
}

// buildSIRCBits emits a SIRC-shaped train with n zero-bits (invalid counts let
// us exercise the exact-12/15/20 gate).
func buildSIRCBits(n int) string {
	t := []int{2400, 600}
	for i := 0; i < n; i++ {
		t = append(t, 600, 600)
	}
	return join(t)
}
