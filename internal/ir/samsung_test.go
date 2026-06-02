// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"strconv"
	"strings"
	"testing"
)

// genSamsung builds a Samsung32 raw timing train: a 4500/4500 leader then 32
// pulse-distance bits of [addr, addr, cmd, ~cmd], each byte LSB-first.
func genSamsung(addr, cmd byte) string {
	bytes := []byte{addr, addr, cmd, cmd ^ 0xFF}
	t := []int{samsungLeaderMark, samsungLeaderSpace}
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

func TestDecodeSamsung_RoundTrip(t *testing.T) {
	cases := []struct{ addr, cmd byte }{
		{0x00, 0x00}, {0x07, 0x02}, {0xE0, 0xE0}, {0xFF, 0x12}, {0x07, 0x99},
	}
	for _, c := range cases {
		r, err := DecodeRaw(genSamsung(c.addr, c.cmd))
		if err != nil {
			t.Fatalf("addr=%02X cmd=%02X: %v", c.addr, c.cmd, err)
		}
		if r.Protocol != "Samsung32" {
			t.Errorf("addr=%02X cmd=%02X: protocol=%s want Samsung32", c.addr, c.cmd, r.Protocol)
		}
		if r.Address != int(c.addr) || r.Command != int(c.cmd) {
			t.Errorf("addr/cmd = %02X/%02X, want %02X/%02X", r.Address, r.Command, c.addr, c.cmd)
		}
		if !r.ChecksumValid {
			t.Errorf("addr=%02X cmd=%02X: command inversion should validate", c.addr, c.cmd)
		}
	}
}

// TestDecodeSamsung_HandVector: addr 0x07 cmd 0x02 -> bytes 07 07 02 FD.
func TestDecodeSamsung_HandVector(t *testing.T) {
	r, err := DecodeRaw(genSamsung(0x07, 0x02))
	if err != nil {
		t.Fatal(err)
	}
	if r.RawBytesHex != "070702FD" {
		t.Errorf("raw bytes = %s, want 070702FD", r.RawBytesHex)
	}
	if r.AddressHex != "0x7" || r.CommandHex != "0x02" {
		t.Errorf("hex = %s/%s, want 0x7/0x02", r.AddressHex, r.CommandHex)
	}
}

// TestDecodeSamsung_16bitAddress: distinct address bytes, valid command
// inverse -> 16-bit address variant.
func TestDecodeSamsung_16bitAddress(t *testing.T) {
	bytes := []byte{0x12, 0x34, 0x56, 0xA9} // 0xA9 == ~0x56
	tt := []int{samsungLeaderMark, samsungLeaderSpace}
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
	if r.Protocol != "Samsung32 (16-bit address)" || r.Address != 0x3412 || r.Command != 0x56 {
		t.Errorf("got %s addr=%X cmd=%X, want 16-bit 3412/56", r.Protocol, r.Address, r.Command)
	}
	if !r.ChecksumValid {
		t.Error("command inversion should validate the 16-bit variant")
	}
}

func TestDecodeSamsung_ChecksumFail(t *testing.T) {
	bytes := []byte{0x07, 0x07, 0x02, 0x02} // byte3 != ~byte2
	tt := []int{samsungLeaderMark, samsungLeaderSpace}
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

func TestDecodeSamsung_Tolerance(t *testing.T) {
	raw := genSamsung(0x07, 0x02)
	parts := strings.Fields(raw)
	scaled := make([]string, len(parts))
	for i, p := range parts {
		n, _ := strconv.Atoi(p)
		scaled[i] = strconv.Itoa(n * 112 / 100) // +12% drift
	}
	r, err := DecodeRaw(strings.Join(scaled, " "))
	if err != nil {
		t.Fatalf("scaled Samsung should still decode: %v", err)
	}
	if r.Protocol != "Samsung32" || r.Address != 0x07 || r.Command != 0x02 {
		t.Errorf("scaled decode = %s %X/%X", r.Protocol, r.Address, r.Command)
	}
}
