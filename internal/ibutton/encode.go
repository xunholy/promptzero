// SPDX-License-Identifier: AGPL-3.0-or-later

package ibutton

import (
	"fmt"
	"strings"
)

// Encode builds a complete, well-formed 8-byte Dallas 1-Wire ROM ID
// from a family code and a 48-bit serial, computing the Dallas/Maxim
// CRC-8 over the first seven bytes — the inverse of Decode. It returns
// the assembled 8 bytes plus the decoded view (CRCValid always true)
// for confirmation.
//
// This is what an operator writes to a blank/magic iButton (a clone):
// pick the family (0x01 DS1990A is the canonical access-control key),
// supply the 48-bit serial read off the target key, and the CRC byte
// is filled in so the ROM passes a reader's integrity check. It is the
// host-side construction step only — actually burning the ROM is a
// hardware op (ibutton_write in internal/flipper); this transmits
// nothing, so it is Low risk like the decoder.
//
// # Wrap-vs-native judgement
//
// Native, and the exact inverse of the existing Decode path: it reuses
// the same computeCRC (Maxim AN-27 polynomial 0x31, reflected) so the
// two are guaranteed consistent. The ROM-ID layout is the public Maxim
// 1-Wire structure (family byte, 48-bit serial, CRC byte); pure byte
// assembly, no hardware, no vendor SDK. Correctness is verifiable two
// ways: round-trip against Decode and the canonical Maxim AN-27 vector
// (family 0x02, serial 1C B8 01 00 00 00 → CRC 0xA2).
//
// The serial must be exactly 6 bytes (48 bits) in the same natural
// left-to-right byte order Decode renders in SerialHex.
func Encode(familyCode byte, serialHex string) ([]byte, *Dallas, error) {
	serial, err := parseHex(serialHex)
	if err != nil {
		return nil, nil, err
	}
	if len(serial) != 6 {
		return nil, nil, fmt.Errorf(
			"ibutton: serial must be exactly 6 bytes (48 bits); got %d byte(s) from %q",
			len(serial), strings.TrimSpace(serialHex))
	}
	rom := make([]byte, 0, 8)
	rom = append(rom, familyCode)
	rom = append(rom, serial...)
	rom = append(rom, computeCRC(rom[:7]))
	d, err := DecodeBytes(rom)
	if err != nil {
		return nil, nil, err
	}
	return rom, d, nil
}
