// SPDX-License-Identifier: AGPL-3.0-or-later

package pocsag

import (
	"fmt"
	"math/bits"
	"strings"
)

// bchGenerator is the POCSAG BCH(31,21) generator polynomial
// g(x) = x^10 + x^9 + x^8 + x^6 + x^5 + x^3 + 1 (ITU-R M.584-2).
const bchGenerator uint32 = 0x769

// preambleBits is the standard POCSAG preamble length — ≥576 bits of
// alternating 1010… so a receiver can establish bit sync before the first
// sync word.
const preambleBits = 576

// SynthInput describes a page to encode. Address is the 21-bit RIC; the low
// 3 bits select the batch frame the address codeword must sit in (the
// decoder reconstructs them from that position). Function 0 = numeric,
// 1/2 = alphanumeric, 3 = tone-only (no body).
type SynthInput struct {
	Address  uint32 `json:"address"`
	Function int    `json:"function"`
	Message  string `json:"message"`
}

// bchCheck computes the 10 BCH(31,21) check bits for a 21-bit data field —
// the remainder of data·x^10 mod g(x) over GF(2).
func bchCheck(data21 uint32) uint32 {
	reg := (data21 & 0x1FFFFF) << 10
	for i := 30; i >= 10; i-- {
		if reg&(1<<uint(i)) != 0 {
			reg ^= bchGenerator << uint(i-10)
		}
	}
	return reg & 0x3FF
}

// buildCodeword turns a 21-bit data field (bit 20 = address/message flag,
// bits 19..0 = content) into the full 32-bit POCSAG codeword: 21 data + 10
// BCH check + 1 even-parity bit. Verifiably the inverse of the decoder's
// codeword parse, and reproduces the canonical idle/sync-adjacent words.
func buildCodeword(data21 uint32) uint32 {
	data21 &= 0x1FFFFF
	word := (data21 << 11) | (bchCheck(data21) << 1)
	if bits.OnesCount32(word)%2 == 1 {
		word |= 1 // even parity over all 32 bits
	}
	return word
}

func addressCodeword(ric uint32, fn int) uint32 {
	content := ((ric >> 3) << 2) | uint32(fn&0x3) // 18-bit addrMSB + 2-bit function
	return buildCodeword(content & 0xFFFFF)       // flag bit 20 = 0 (address)
}

func messageCodeword(content20 uint32) uint32 {
	return buildCodeword((1 << 20) | (content20 & 0xFFFFF)) // flag bit 20 = 1 (message)
}

// Synth builds a complete POCSAG transmission (preamble + sync + one batch)
// for a single page — the inverse of Decode. The address codeword is placed
// in the batch frame its low 3 RIC bits demand; message codewords follow;
// unused codewords are idle-filled.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of Decode. POCSAG framing is fully public
// (ITU-R M.584-2): BCH(31,21) over GF(2), even parity, fixed batch layout,
// 4-bit numeric / 7-bit alphanumeric tables — pure bit maths, no crypto, no
// hardware. Unlike the decoder (which only checks parity), Synth computes
// the real BCH so the frame is valid to an actual pager; correctness is
// verifiable three ways: the BCH reproduces the canonical idle codeword,
// round-trip against Decode, and hand-computed codewords. Generation only —
// it transmits nothing (pair with a Sub-GHz TX stage), so it is Low risk
// like the decoder.
//
// # Deliberately bounded
//
// One batch (16 codewords): a message that does not fit after the address
// codeword's frame position errors rather than guessing a multi-batch
// layout (a wrong frame is worse than none). Numeric messages have no
// length field on the wire, so a message that doesn't fill its final
// codeword is space-padded (POCSAG numeric convention).
func Synth(in SynthInput) (string, error) {
	if in.Function < 0 || in.Function > 3 {
		return "", fmt.Errorf("pocsag: function %d out of range (0-3)", in.Function)
	}
	if in.Address > 0x1FFFFF {
		return "", fmt.Errorf("pocsag: address %d exceeds 21-bit RIC range", in.Address)
	}
	enc := encodingForFunction(in.Function)
	if enc == "tone" && in.Message != "" {
		return "", fmt.Errorf("pocsag: function 3 is tone-only; message must be empty")
	}

	msgWords, err := encodeMessage(enc, in.Message)
	if err != nil {
		return "", err
	}

	// Lay the batch out: idle up to the address frame, then address +
	// message, then idle fill.
	addrIdx := int(in.Address&0x7) * FrameCodewords
	if addrIdx+1+len(msgWords) > BatchCodewords {
		return "", fmt.Errorf("pocsag: message needs %d codewords but only %d remain after the address at frame %d "+
			"(single-batch limit; multi-batch deferred)", len(msgWords), BatchCodewords-addrIdx-1, in.Address&0x7)
	}
	batch := make([]uint32, BatchCodewords)
	for i := range batch {
		batch[i] = IdleWord
	}
	batch[addrIdx] = addressCodeword(in.Address, in.Function)
	for i, w := range msgWords {
		batch[addrIdx+1+i] = w
	}

	var sb strings.Builder
	sb.Grow(preambleBits + (1+BatchCodewords)*CodewordBits)
	for i := 0; i < preambleBits; i++ {
		if i%2 == 0 {
			sb.WriteByte('1')
		} else {
			sb.WriteByte('0')
		}
	}
	fmt.Fprintf(&sb, "%032b", SyncWord)
	for _, w := range batch {
		fmt.Fprintf(&sb, "%032b", w)
	}
	return sb.String(), nil
}

// encodeMessage packs the body into 20-bit message-codeword contents,
// matching the decoder's numeric (4-bit, bit-reversed) / alphanumeric
// (7-bit ASCII, bit-reversed) readers.
func encodeMessage(encoding, msg string) ([]uint32, error) {
	if encoding == "tone" {
		return nil, nil
	}
	var payload strings.Builder
	switch encoding {
	case "numeric":
		for _, r := range msg {
			v, ok := numericCode(byte(r))
			if !ok {
				return nil, fmt.Errorf("pocsag: numeric message has unsupported character %q (allowed: 0-9 space U - ( ))", string(r))
			}
			payload.WriteString(reverseBitsString(v, 4))
		}
	case "alphanumeric":
		for _, r := range msg {
			if r > 0x7F {
				return nil, fmt.Errorf("pocsag: alphanumeric message has non-ASCII character %q", string(r))
			}
			payload.WriteString(reverseBitsString(uint32(r), 7))
		}
	}

	bitsStr := payload.String()
	if len(bitsStr) == 0 {
		return nil, nil
	}
	// Pad up to a whole number of 20-bit codewords. Numeric pads with the
	// space code (0xA, bit-reversed); alphanumeric pads with 0 (the decoder
	// strips NUL).
	for len(bitsStr)%20 != 0 {
		if encoding == "numeric" && len(bitsStr)%4 == 0 {
			bitsStr += reverseBitsString(0xA, 4) // space
		} else {
			bitsStr += "0"
		}
	}
	var words []uint32
	for off := 0; off < len(bitsStr); off += 20 {
		var v uint32
		for i := 0; i < 20; i++ {
			v <<= 1
			if bitsStr[off+i] == '1' {
				v |= 1
			}
		}
		words = append(words, messageCodeword(v))
	}
	return words, nil
}

// numericCode returns the 4-bit table index for a numeric-message
// character (the value the decoder's reversed-nibble lookup yields).
func numericCode(c byte) (uint32, bool) {
	for i, t := range pocsagNumericTable {
		if t == c {
			return uint32(i), true
		}
	}
	return 0, false
}

// reverseBitsString renders the low n bits of v, bit-reversed, as an
// n-character MSB-first '0'/'1' string — the on-wire (LSB-first) form the
// decoder reverses back. Mirrors decodeNumeric/decodeAlphanumeric.
func reverseBitsString(v uint32, n int) string {
	rev := bits.Reverse32(v) >> uint(32-n)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		if rev&(1<<uint(n-1-i)) != 0 {
			out[i] = '1'
		} else {
			out[i] = '0'
		}
	}
	return string(out)
}
