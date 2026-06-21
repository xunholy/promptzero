// SPDX-License-Identifier: AGPL-3.0-or-later

package fdxb

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// maxNationalCode is the largest 38-bit national identification number.
const maxNationalCode = (uint64(1) << 38) - 1

// maxCountryCode is the largest 10-bit country code.
const maxCountryCode = (1 << 10) - 1

// Encode builds the 10-byte FDX-B ID+CRC data block (the 8-byte ID block plus
// the 2-byte CRC-16) from a national identification number and country code,
// with optional animal-application and extended-data-block flags. It is the
// exact inverse of Decode: the same LSB-first field layout (national 38 bits at
// offset 0, country 10 bits at offset 38, the two flag bits at 48/49, the
// reserved bits 50..63 left zero) packed MSB-first into bytes, then the same
// crc16FDXB over the first 8 bytes appended LSB-first.
//
// The 24-bit extended data block is out of scope here exactly as in Decode
// (vendor-specific); dataBlock only sets the presence flag. Reserved bits are
// emitted as zero, so the output is the canonical encoding — a real tag that
// carried vendor bits in the reserved field would round-trip its national /
// country / flags / CRC but not those raw reserved bits.
func Encode(nationalCode uint64, countryCode int, animal, dataBlock bool) ([]byte, error) {
	if nationalCode > maxNationalCode {
		return nil, fmt.Errorf("fdxb: national code %d exceeds the 38-bit maximum %d", nationalCode, maxNationalCode)
	}
	if countryCode < 0 || countryCode > maxCountryCode {
		return nil, fmt.Errorf("fdxb: country code %d out of range 0..%d", countryCode, maxCountryCode)
	}

	bits := make([]int, 80) // 8-byte ID block + 2-byte CRC
	writeLSBF(bits, 0, 38, nationalCode)
	writeLSBF(bits, 38, 10, uint64(countryCode))
	if dataBlock {
		bits[48] = 1
	}
	if animal {
		bits[49] = 1
	}
	// bits 50..63 reserved — left zero.

	idBlock := bitsToBytesMSBF(bits[:64])
	crc := crc16FDXB(idBlock)
	writeLSBF(bits, 64, 16, uint64(crc))
	return bitsToBytesMSBF(bits), nil
}

// EncodeHex is the hex-string convenience wrapper, returning the upper-case hex
// of the 10-byte block.
func EncodeHex(nationalCode uint64, countryCode int, animal, dataBlock bool) (string, error) {
	b, err := Encode(nationalCode, countryCode, animal, dataBlock)
	if err != nil {
		return "", err
	}
	return strings.ToUpper(hex.EncodeToString(b)), nil
}

// writeLSBF writes the low n bits of v into bits[off..off+n), least-significant
// bit first — the inverse of readLSBF.
func writeLSBF(bits []int, off, n int, v uint64) {
	for i := 0; i < n; i++ {
		bits[off+i] = int((v >> uint(i)) & 1)
	}
}

// bitsToBytesMSBF packs a bit slice (length a multiple of 8) into bytes,
// most-significant bit first within each byte — the inverse of toBitsMSBF.
func bitsToBytesMSBF(bits []int) []byte {
	out := make([]byte, len(bits)/8)
	for i := range out {
		var x byte
		for j := 0; j < 8; j++ {
			x |= byte(bits[i*8+j]&1) << uint(7-j)
		}
		out[i] = x
	}
	return out
}
