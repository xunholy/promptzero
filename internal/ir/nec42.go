// SPDX-License-Identifier: AGPL-3.0-or-later

package ir

import "fmt"

// NEC42 is the 42-bit NEC-family variant: it shares NEC's 9000µs/4500µs leader
// and 560µs pulse-distance bit encoding, but carries a 13-bit address + 8-bit
// command (each followed by its bitwise inverse) instead of NEC's 8+8. A NEC42
// frame is distinguished from a standard 32-bit NEC frame purely by its bit
// count (42 vs 32). The 42 bits, transmitted LSB-first, are: 13-bit address,
// 13-bit address-inverse, 8-bit command, 8-bit command-inverse. The two inverse
// fields are the checksum — when they hold the frame is NEC42 (13/8); when they
// do not it is reported as NEC42ext (a 26-bit address + 16-bit command, no
// inversion), exactly mirroring the Flipper firmware's interpret logic.

// countNECBits counts the valid NEC pulse-distance bit-pairs (560µs mark +
// 560/1690µs space) starting at t[2], capped at 42, so DecodeRaw can route a
// 42-bit NEC42 frame away from the 32-bit NEC path.
func countNECBits(t []int) int {
	n := 0
	for i := 2; i+1 < len(t) && n < 42; i += 2 {
		if !within(t[i], necBitMark) {
			break
		}
		if !within(t[i+1], necZeroSpace) && !within(t[i+1], necOneSpace) {
			break
		}
		n++
	}
	return n
}

// readNECBits reads n NEC pulse-distance bits from t[2:], LSB-first, into a
// uint64.
func readNECBits(t []int, n int) (uint64, error) {
	var data uint64
	for bit := 0; bit < n; bit++ {
		i := 2 + bit*2
		if i+1 >= len(t) {
			return 0, fmt.Errorf("ir: NEC42 frame truncated at bit %d (need %d)", bit, n)
		}
		if !within(t[i], necBitMark) {
			return 0, fmt.Errorf("ir: NEC42 bit %d mark %dµs not ~560µs", bit, t[i])
		}
		switch {
		case within(t[i+1], necOneSpace):
			data |= 1 << uint(bit)
		case within(t[i+1], necZeroSpace):
			// zero bit
		default:
			return 0, fmt.Errorf("ir: NEC42 bit %d space %dµs is neither ~560µs (0) nor ~1690µs (1)", bit, t[i+1])
		}
	}
	return data, nil
}

// decodeNEC42 decodes a 42-bit NEC42 frame (the leader at t[0..1] already
// matched NEC's 9000/4500). The 13-bit address and 8-bit command are each
// followed by their inverse; NEC42 is reported only when BOTH inversions hold,
// otherwise the frame is surfaced as NEC42ext (26-bit address + 16-bit command)
// rather than asserting a 13/8 split that the checksum did not confirm.
func decodeNEC42(t []int) (*Result, error) {
	data, err := readNECBits(t, 42)
	if err != nil {
		return nil, err
	}
	address := int(data & 0x1FFF)
	addrInverse := int((data >> 13) & 0x1FFF)
	command := int((data >> 26) & 0xFF)
	cmdInverse := int((data >> 34) & 0xFF)
	addrOK := address == (^addrInverse & 0x1FFF)
	cmdOK := command == (^cmdInverse & 0xFF)

	out := &Result{
		Bits:        42,
		RawBytesHex: fmt.Sprintf("%011X", data&0x3FFFFFFFFFF),
	}
	if addrOK && cmdOK {
		out.Protocol = "NEC42"
		out.Address = address
		out.Command = command
		out.ChecksumValid = true
		out.Notes = []string{"NEC42 — 13-bit address + 8-bit command, both inverse-field checksums validate"}
	} else {
		out.Protocol = "NEC42ext"
		out.Address = address | (addrInverse << 13) // 26-bit
		out.Command = command | (cmdInverse << 8)   // 16-bit
		out.Notes = []string{"NEC42ext: 26-bit address + 16-bit command (no inversion) — the inverse-field checksum did not hold"}
	}
	out.AddressHex = fmt.Sprintf("0x%X", out.Address)
	out.CommandHex = fmt.Sprintf("0x%02X", out.Command)
	return out, nil
}

// encodeNEC42 builds a 42-bit NEC42 timing list (the inverse of decodeNEC42)
// from a 13-bit address + 8-bit command, emitting both inverse fields.
func encodeNEC42(address, command int) []int {
	var data uint64
	data |= uint64(address & 0x1FFF)
	data |= uint64((^address)&0x1FFF) << 13
	data |= uint64(command&0xFF) << 26
	data |= uint64((^command)&0xFF) << 34

	t := []int{necLeaderMark, necLeaderSpace}
	for bit := 0; bit < 42; bit++ {
		t = append(t, necBitMark)
		if data&(1<<uint(bit)) != 0 {
			t = append(t, necOneSpace)
		} else {
			t = append(t, necZeroSpace)
		}
	}
	return append(t, necBitMark) // trailing stop mark
}
