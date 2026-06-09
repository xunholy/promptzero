// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "testing"

// nec42Values are the non-trivial (13-bit address, 8-bit command) pairs the
// Flipper firmware's own NEC42 encode/decode test round-trips as NEC42
// (applications/debug/unit_tests/resources/unit_tests/infrared/test_nec42.irtest,
// encoder_decoder_input1: 0x1FFF/0xFF, 0x0AAA/0x55, 0x01/0x00, 0x00/0x80, …).
// Our encode↔decode reproducing these exact values confirms our bit layout
// matches the firmware's interpret formula.
var nec42Values = []struct{ addr, cmd int }{
	{0x0000, 0x00}, {0x0001, 0x00}, {0x0001, 0x80}, {0x0000, 0x80},
	{0x1FFF, 0xFF}, {0x1FFE, 0xFF}, {0x1FFE, 0x7F}, {0x1FFF, 0x7F},
	{0x0AAA, 0x55}, {0x1234, 0x5A}, {0x0042, 0x13},
}

func TestNEC42_RoundTrip(t *testing.T) {
	for _, v := range nec42Values {
		enc, err := EncodeRaw("NEC42", v.addr, v.cmd, EncodeOptions{})
		if err != nil {
			t.Fatalf("encode 0x%X/0x%02X: %v", v.addr, v.cmd, err)
		}
		res, err := DecodeRaw(enc)
		if err != nil {
			t.Fatalf("decode of encoded 0x%X/0x%02X: %v", v.addr, v.cmd, err)
		}
		if res.Protocol != "NEC42" {
			t.Errorf("0x%X/0x%02X: protocol = %q, want NEC42", v.addr, v.cmd, res.Protocol)
		}
		if res.Address != v.addr || res.Command != v.cmd || !res.ChecksumValid {
			t.Errorf("round-trip 0x%X/0x%02X -> 0x%X/0x%02X (valid=%v)", v.addr, v.cmd, res.Address, res.Command, res.ChecksumValid)
		}
		if res.Bits != 42 {
			t.Errorf("0x%X/0x%02X: bits = %d, want 42", v.addr, v.cmd, res.Bits)
		}
	}
}

// TestNEC42_HandVector independently builds a 42-bit NEC42 frame for a known
// address/command (NOT via encodeNEC42) and confirms the decoder reads the
// firmware's bit layout: addr(13) | ~addr(13) | cmd(8) | ~cmd(8), LSB-first.
func TestNEC42_HandVector(t *testing.T) {
	addr, cmd := 0x0AAA, 0x55
	var data uint64
	data |= uint64(addr & 0x1FFF)
	data |= uint64((^addr)&0x1FFF) << 13
	data |= uint64(cmd&0xFF) << 26
	data |= uint64((^cmd)&0xFF) << 34
	// Emit NEC pulse-distance timings directly from the bit pattern.
	timings := []int{necLeaderMark, necLeaderSpace}
	for bit := 0; bit < 42; bit++ {
		timings = append(timings, necBitMark)
		if data&(1<<uint(bit)) != 0 {
			timings = append(timings, necOneSpace)
		} else {
			timings = append(timings, necZeroSpace)
		}
	}
	timings = append(timings, necBitMark)
	s := joinInts(timings)
	res, err := DecodeRaw(s)
	if err != nil {
		t.Fatalf("decode hand vector: %v", err)
	}
	if res.Protocol != "NEC42" || res.Address != addr || res.Command != cmd {
		t.Errorf("hand vector -> %q 0x%X/0x%02X, want NEC42 0x%X/0x%02X", res.Protocol, res.Address, res.Command, addr, cmd)
	}
}

// TestNEC42_DoesNotStealNEC32 confirms a standard 32-bit NEC frame still decodes
// as NEC (the bit-count dispatch must not misroute it to NEC42).
func TestNEC42_DoesNotStealNEC32(t *testing.T) {
	enc, err := EncodeRaw("NEC", 0x04, 0x08, EncodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	res, err := DecodeRaw(enc)
	if err != nil {
		t.Fatalf("decode NEC: %v", err)
	}
	if res.Protocol != "NEC" {
		t.Errorf("32-bit NEC misrouted to %q", res.Protocol)
	}
	if res.Address != 0x04 || res.Command != 0x08 {
		t.Errorf("NEC decode = 0x%X/0x%02X, want 0x04/0x08", res.Address, res.Command)
	}
}

// TestNEC42ext covers the no-inversion path: a 42-bit frame whose inverse
// fields do not hold is surfaced as NEC42ext, not asserted as NEC42.
func TestNEC42ext(t *testing.T) {
	// Build a frame with arbitrary fields that break the inverse relationship.
	var data uint64
	data |= uint64(0x1ABC & 0x1FFF)     // address
	data |= uint64(0x0123&0x1FFF) << 13 // address_inverse (NOT ~addr)
	data |= uint64(0x9A&0xFF) << 26     // command
	data |= uint64(0x42&0xFF) << 34     // command_inverse (NOT ~cmd)
	timings := []int{necLeaderMark, necLeaderSpace}
	for bit := 0; bit < 42; bit++ {
		timings = append(timings, necBitMark)
		if data&(1<<uint(bit)) != 0 {
			timings = append(timings, necOneSpace)
		} else {
			timings = append(timings, necZeroSpace)
		}
	}
	timings = append(timings, necBitMark)
	res, err := DecodeRaw(joinInts(timings))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Protocol != "NEC42ext" {
		t.Errorf("protocol = %q, want NEC42ext", res.Protocol)
	}
	if res.ChecksumValid {
		t.Errorf("NEC42ext must not be checksum-valid")
	}
}

// TestNEC42_AddressRange rejects an out-of-range (>13-bit) address on encode.
func TestNEC42_AddressRange(t *testing.T) {
	if _, err := EncodeRaw("NEC42", 0x2000, 0x00, EncodeOptions{}); err == nil {
		t.Error("expected range error for 14-bit address")
	}
}
