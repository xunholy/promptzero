// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"strconv"
	"strings"
	"testing"
)

// genNEC builds a standard NEC raw timing train for an 8-bit address and
// command (address, ~address, command, ~command — each LSB-first). It is the
// round-trip anchor for the decoder: a test-only encoder, not a shipped tool.
func genNEC(addr, cmd byte) string {
	bytes := []byte{addr, addr ^ 0xFF, cmd, cmd ^ 0xFF}
	t := []int{necLeaderMark, necLeaderSpace}
	for _, by := range bytes {
		for bit := 0; bit < 8; bit++ {
			t = append(t, necBitMark)
			if by&(1<<uint(bit)) != 0 {
				t = append(t, necOneSpace)
			} else {
				t = append(t, necZeroSpace)
			}
		}
	}
	t = append(t, necBitMark) // trailing stop mark
	return join(t)
}

func join(t []int) string {
	parts := make([]string, len(t))
	for i, v := range t {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, " ")
}

func TestDecodeRaw_NEC_RoundTrip(t *testing.T) {
	cases := []struct{ addr, cmd byte }{
		{0x00, 0x00}, {0xFF, 0xFF}, {0x04, 0x08}, {0x20, 0x10}, {0xA5, 0x5A},
	}
	for _, c := range cases {
		r, err := DecodeRaw(genNEC(c.addr, c.cmd))
		if err != nil {
			t.Fatalf("addr=%02X cmd=%02X: %v", c.addr, c.cmd, err)
		}
		if r.Protocol != "NEC" {
			t.Errorf("addr=%02X cmd=%02X: protocol=%s want NEC", c.addr, c.cmd, r.Protocol)
		}
		if r.Address != int(c.addr) || r.Command != int(c.cmd) {
			t.Errorf("addr/cmd = %02X/%02X, want %02X/%02X", r.Address, r.Command, c.addr, c.cmd)
		}
		if !r.ChecksumValid {
			t.Errorf("addr=%02X cmd=%02X: checksum should be valid", c.addr, c.cmd)
		}
	}
}

// TestDecodeRaw_HandVector checks a vector independent of genNEC: address 0x04,
// command 0x08 — bytes 04 FB 08 F7, address inversion 04^FB==FF, command
// inversion 08^F7==FF both hold.
func TestDecodeRaw_HandVector(t *testing.T) {
	r, err := DecodeRaw(genNEC(0x04, 0x08))
	if err != nil {
		t.Fatal(err)
	}
	if r.RawBytesHex != "04FB08F7" {
		t.Errorf("raw bytes = %s, want 04FB08F7", r.RawBytesHex)
	}
	if r.AddressHex != "0x4" || r.CommandHex != "0x08" {
		t.Errorf("hex = %s/%s, want 0x4/0x08", r.AddressHex, r.CommandHex)
	}
}

func TestDecodeRaw_Extended(t *testing.T) {
	// Extended NEC: 16-bit address with no inversion (b0=0x12, b1=0x34), but a
	// valid command inversion (cmd=0x56, ~cmd=0xA9).
	bytes := []byte{0x12, 0x34, 0x56, 0xA9}
	tt := []int{necLeaderMark, necLeaderSpace}
	for _, by := range bytes {
		for bit := 0; bit < 8; bit++ {
			tt = append(tt, necBitMark)
			if by&(1<<uint(bit)) != 0 {
				tt = append(tt, necOneSpace)
			} else {
				tt = append(tt, necZeroSpace)
			}
		}
	}
	tt = append(tt, necBitMark)
	r, err := DecodeRaw(join(tt))
	if err != nil {
		t.Fatal(err)
	}
	if r.Protocol != "NEC-extended" {
		t.Errorf("protocol = %s, want NEC-extended", r.Protocol)
	}
	if r.Address != 0x3412 || r.Command != 0x56 {
		t.Errorf("addr/cmd = %X/%X, want 3412/56", r.Address, r.Command)
	}
	if !r.ChecksumValid {
		t.Error("command inversion should validate extended frame")
	}
}

func TestDecodeRaw_ChecksumFail(t *testing.T) {
	// Neither inversion holds -> NEC-like, checksum invalid, no confident decode.
	bytes := []byte{0x12, 0x34, 0x56, 0x78}
	tt := []int{necLeaderMark, necLeaderSpace}
	for _, by := range bytes {
		for bit := 0; bit < 8; bit++ {
			tt = append(tt, necBitMark)
			if by&(1<<uint(bit)) != 0 {
				tt = append(tt, necOneSpace)
			} else {
				tt = append(tt, necZeroSpace)
			}
		}
	}
	r, err := DecodeRaw(join(tt))
	if err != nil {
		t.Fatal(err)
	}
	if r.ChecksumValid {
		t.Error("checksum should be invalid")
	}
	if !strings.Contains(r.Protocol, "checksum failed") {
		t.Errorf("protocol = %s, want checksum-failed marker", r.Protocol)
	}
}

func TestDecodeRaw_Repeat(t *testing.T) {
	r, err := DecodeRaw("9000 2250 560")
	if err != nil {
		t.Fatal(err)
	}
	if r.Protocol != "NEC-repeat" {
		t.Errorf("protocol = %s, want NEC-repeat", r.Protocol)
	}
}

func TestDecodeRaw_Tolerance(t *testing.T) {
	// Real captures drift; ±25% should still decode. Scale every timing by 1.1.
	raw := genNEC(0x04, 0x08)
	parts := strings.Fields(raw)
	scaled := make([]string, len(parts))
	for i, p := range parts {
		n, _ := strconv.Atoi(p)
		scaled[i] = strconv.Itoa(n * 110 / 100)
	}
	r, err := DecodeRaw(strings.Join(scaled, " "))
	if err != nil {
		t.Fatalf("scaled capture should still decode: %v", err)
	}
	if r.Protocol != "NEC" || r.Address != 0x04 {
		t.Errorf("scaled decode = %s addr %X, want NEC 04", r.Protocol, r.Address)
	}
}

func TestDecodeRaw_Errors(t *testing.T) {
	bad := []string{
		"",                   // empty
		"600 4500",           // leader mark not ~9000
		"9000 8000",          // leader space neither 4500 nor 2250
		"9000 4500 560 560",  // truncated (1 bit, need 32)
		"9000 4500 560 3000", // bit space out of range
		"abc def",            // non-integer
	}
	for _, s := range bad {
		if _, err := DecodeRaw(s); err == nil {
			t.Errorf("input %q: expected error", s)
		}
	}
}
