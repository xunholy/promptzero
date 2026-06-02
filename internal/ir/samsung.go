// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "fmt"

// Samsung32 nominal leader timings in microseconds. Samsung shares NEC's
// pulse-distance bit encoding (560µs mark + 560µs/1690µs space, via
// readPDC32) but uses an equal 4500µs/4500µs leader instead of NEC's
// 9000µs/4500µs — which is how DecodeRaw tells the two apart.
const (
	samsungLeaderMark  = 4500
	samsungLeaderSpace = 4500
)

// decodeSamsung decodes a Samsung32 frame from its parsed timings (the 4500µs
// leader mark is at t[0]). The 32-bit frame is address · address · command ·
// ~command (LSB-first per byte): the command byte's bitwise inverse is a
// built-in checksum, so a frame is reported as Samsung32 only when byte3 ==
// ~byte2 holds, and otherwise the raw bytes are surfaced with a note rather
// than a guessed address/command — no confidently-wrong output.
func decodeSamsung(t []int) (*Result, error) {
	if !within(t[1], samsungLeaderSpace) {
		return nil, fmt.Errorf("ir: Samsung leader space %dµs is not ~4500µs", t[1])
	}
	b, err := readPDC32(t)
	if err != nil {
		return nil, err
	}
	out := &Result{
		Bits:        32,
		RawBytesHex: fmt.Sprintf("%02X%02X%02X%02X", b[0], b[1], b[2], b[3]),
	}
	cmdInv := b[3] == b[2]^0xFF
	addrDup := b[1] == b[0]
	switch {
	case cmdInv && addrDup:
		out.Protocol = "Samsung32"
		out.Address = int(b[0])
		out.Command = int(b[2])
		out.ChecksumValid = true
	case cmdInv:
		out.Protocol = "Samsung32 (16-bit address)"
		out.Address = int(b[0]) | int(b[1])<<8
		out.Command = int(b[2])
		out.ChecksumValid = true
		out.Notes = append(out.Notes, "address bytes differ — treated as a 16-bit address; command inversion validates")
	default:
		out.Protocol = "Samsung-like (checksum failed)"
		out.Address = int(b[0])
		out.Command = int(b[2])
		out.Notes = append(out.Notes, "command inversion (byte3 == ~byte2) does not hold — a misread frame or a non-Samsung pulse-distance protocol; address/command shown unverified")
	}
	out.AddressHex = fmt.Sprintf("0x%X", out.Address)
	out.CommandHex = fmt.Sprintf("0x%02X", out.Command)
	return out, nil
}
