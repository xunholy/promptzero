// SPDX-License-Identifier: AGPL-3.0-or-later

package cyfral

import (
	"encoding/hex"
	"strings"
)

// bitsNibble is the inverse of nibbleBits: index by the 2-bit value to get the
// on-wire data nibble (00->0x7, 01->0xB, 10->0xD, 11->0xE).
var bitsNibble = [4]byte{0x7, 0xB, 0xD, 0xE}

// Encode builds the 40-bit (5-byte) on-wire Cyfral frame for a 16-bit key — the
// exact inverse of Decode. The frame is a 0b0001 start nibble, eight data
// nibbles encoding the key two bits at a time (most-significant pair first,
// mapping 11->E / 10->D / 01->B / 00->7), and a 0b0001 stop nibble, packed
// MSB-nibble first into 5 bytes. Every 16-bit key produces a structurally valid
// frame (the format carries no checksum beyond the nibble constraints, which
// the encoding satisfies by construction), so it round-trips with Decode for
// any key.
func Encode(key uint16) []byte {
	nib := make([]byte, 10)
	nib[0] = 0x1 // start
	nib[9] = 0x1 // stop
	for i := 1; i <= 8; i++ {
		shift := uint(2 * (8 - i)) // nib[1] = highest pair, nib[8] = lowest
		nib[i] = bitsNibble[(key>>shift)&0b11]
	}
	out := make([]byte, 5)
	for i := 0; i < 5; i++ {
		out[i] = nib[i*2]<<4 | nib[i*2+1]
	}
	return out
}

// EncodeHex returns the upper-case hex of the 5-byte on-wire frame.
func EncodeHex(key uint16) string {
	return strings.ToUpper(hex.EncodeToString(Encode(key)))
}
