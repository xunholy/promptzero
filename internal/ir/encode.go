// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import (
	"fmt"
	"strings"
)

// EncodeOptions carries the per-protocol extras EncodeRaw needs beyond the
// address/command: the Sony SIRC frame width, the RC5 toggle bit, and the
// SIRC 20-bit extension.
type EncodeOptions struct {
	SIRCBits int // 12 (default), 15 or 20 — Sony SIRC frame width
	Toggle   int // 0/1 — RC5 toggle bit
	Ext      int // SIRC 20-bit extension byte
	Vendor   int // Kaseikyo 16-bit vendor ID (default 0x2002 Panasonic)
}

// EncodeRaw generates the raw IR timing sequence (space-separated microsecond
// mark/space durations) for a consumer-IR frame — the inverse of DecodeRaw. The
// emitted timings round-trip through DecodeRaw to the same protocol + address +
// command. It is the offline complement to the device-side ir_build, and the
// timings can be fed to EncodePronto to produce a shareable Pronto code.
//
// Supported: NEC (8-bit address + command, both inverse-byte checksums emitted),
// NEC-extended (16-bit address, command inversion only), the NEC-repeat code,
// Samsung32 (address·address·command·~command), Sony SIRC (12/15/20-bit),
// Philips RC5 / RC5X (14-bit Manchester; a command > 63 emits an RC5X frame),
// and Kaseikyo (Panasonic/Denon/JVC/Sharp/Mitsubishi — 48-bit, vendor via
// opt.Vendor, both the vendor parity and the frame parity computed).
func EncodeRaw(protocol string, address, command int, opt EncodeOptions) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "NEC":
		if err := inRange("address", address, 0, 255); err != nil {
			return "", err
		}
		if err := inRange("command", command, 0, 255); err != nil {
			return "", err
		}
		bytes := []byte{byte(address), byte(address) ^ 0xFF, byte(command), byte(command) ^ 0xFF}
		return joinInts(emitPDC(necLeaderMark, necLeaderSpace, bytes)), nil

	case "NECEXT", "NEC-EXTENDED", "NECX":
		if err := inRange("address", address, 0, 0xFFFF); err != nil { // 16-bit, no inversion
			return "", err
		}
		if err := inRange("command", command, 0, 255); err != nil {
			return "", err
		}
		bytes := []byte{byte(address), byte(address >> 8), byte(command), byte(command) ^ 0xFF}
		return joinInts(emitPDC(necLeaderMark, necLeaderSpace, bytes)), nil

	case "NEC-REPEAT", "NEC-RPT", "NECREPEAT":
		// The NEC repeat code: leader mark + the shorter 2250µs repeat space +
		// a single stop mark. Carries no address/command.
		return joinInts([]int{necLeaderMark, necRepeatSpace, necBitMark}), nil

	case "SAMSUNG", "SAMSUNG32":
		if err := inRange("address", address, 0, 255); err != nil {
			return "", err
		}
		if err := inRange("command", command, 0, 255); err != nil {
			return "", err
		}
		bytes := []byte{byte(address), byte(address), byte(command), byte(command) ^ 0xFF}
		return joinInts(emitPDC(samsungLeaderMark, samsungLeaderSpace, bytes)), nil

	case "SIRC", "SONY":
		return encodeSIRC(address, command, opt)

	case "RC5", "RC5X":
		return encodeRC5(address, command, opt.Toggle)

	case "KASEIKYO", "PANASONIC":
		return encodeKaseikyo(address, command, opt.Vendor)

	default:
		return "", fmt.Errorf("ir: unsupported encode protocol %q (NEC, Samsung32, SIRC, RC5)", protocol)
	}
}

// emitPDC emits a pulse-distance (NEC-family) frame: leader, then each byte
// LSB-first as bitMark + zero/one space, then a trailing stop mark.
func emitPDC(leaderMark, leaderSpace int, bytes []byte) []int {
	t := []int{leaderMark, leaderSpace}
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
	return append(t, necBitMark) // trailing stop mark
}

func encodeSIRC(address, command int, opt EncodeOptions) (string, error) {
	bits := opt.SIRCBits
	if bits == 0 {
		bits = 12
	}
	var addrBits, extBits int
	switch bits {
	case 12:
		addrBits, extBits = 5, 0
	case 15:
		addrBits, extBits = 8, 0
	case 20:
		addrBits, extBits = 5, 8
	default:
		return "", fmt.Errorf("ir: SIRC frame width must be 12, 15 or 20 (got %d)", bits)
	}
	if err := inRange("command", command, 0, 127); err != nil { // 7-bit command
		return "", err
	}
	if err := inRange("address", address, 0, (1<<addrBits)-1); err != nil {
		return "", err
	}
	if err := inRange("ext", opt.Ext, 0, maxExt(extBits)); err != nil {
		return "", err
	}

	var seq []int
	for i := 0; i < 7; i++ {
		seq = append(seq, (command>>i)&1)
	}
	for i := 0; i < addrBits; i++ {
		seq = append(seq, (address>>i)&1)
	}
	for i := 0; i < extBits; i++ {
		seq = append(seq, (opt.Ext>>i)&1)
	}

	t := []int{sircLeaderMark, sircLeaderSpace}
	for _, b := range seq {
		if b == 1 {
			t = append(t, sircOneMark)
		} else {
			t = append(t, sircZeroMark)
		}
		t = append(t, sircBitSpace)
	}
	return joinInts(t), nil
}

func encodeRC5(address, command, toggle int) (string, error) {
	if err := inRange("address", address, 0, 31); err != nil { // 5-bit
		return "", err
	}
	if err := inRange("command", command, 0, 127); err != nil { // RC5X extends to 7-bit
		return "", err
	}
	if toggle != 0 && toggle != 1 {
		return "", fmt.Errorf("ir: RC5 toggle must be 0 or 1 (got %d)", toggle)
	}
	s2 := 1 - ((command >> 6) & 1) // S2 carries the inverted 7th command bit (RC5X)
	six := command & 0x3F
	bits := []int{1, s2, toggle}
	for i := 4; i >= 0; i-- {
		bits = append(bits, (address>>i)&1)
	}
	for i := 5; i >= 0; i-- {
		bits = append(bits, (six>>i)&1)
	}
	// Manchester half-bit levels: 1 -> off,on ; 0 -> on,off.
	var half []bool
	for _, b := range bits {
		if b == 1 {
			half = append(half, false, true)
		} else {
			half = append(half, true, false)
		}
	}
	half = half[1:] // drop S1's leading off (a capture starts at the first mark)
	var out []int
	for i := 0; i < len(half); {
		j := i
		for j < len(half) && half[j] == half[i] {
			j++
		}
		out = append(out, (j-i)*rc5HalfBit)
		i = j
	}
	return joinInts(out), nil
}

// encodeKaseikyo emits a 48-bit Kaseikyo frame (the inverse of decodeKaseikyo).
// vendor defaults to Panasonic (0x2002) when 0.
func encodeKaseikyo(address, command, vendor int) (string, error) {
	if vendor == 0 {
		vendor = 0x2002 // Panasonic
	}
	if err := inRange("vendor", vendor, 0, 0xFFFF); err != nil {
		return "", err
	}
	if err := inRange("address", address, 0, 0xFFF); err != nil { // 12-bit
		return "", err
	}
	if err := inRange("command", command, 0, 0xFF); err != nil { // 8-bit
		return "", err
	}
	v := uint16(vendor)
	var b [6]byte
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = (kaseikyoVendorParity(v) & 0x0F) | byte((address&0xF)<<4)
	b[3] = byte(address >> 4)
	b[4] = byte(command)
	b[5] = b[2] ^ b[3] ^ b[4] // frame parity

	t := []int{kaseikyoHeaderMark, kaseikyoHeaderSpace}
	for _, by := range b {
		for bit := 0; bit < 8; bit++ {
			t = append(t, kaseikyoBitMark)
			if by&(1<<uint(bit)) != 0 {
				t = append(t, kaseikyoOneSpace)
			} else {
				t = append(t, kaseikyoZeroSpace)
			}
		}
	}
	return joinInts(t), nil
}

func maxExt(extBits int) int {
	if extBits == 0 {
		return 0
	}
	return (1 << extBits) - 1
}

func inRange(name string, v, lo, hi int) error {
	if v < lo || v > hi {
		return fmt.Errorf("ir: %s %d out of range [%d, %d]", name, v, lo, hi)
	}
	return nil
}
