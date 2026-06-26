// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthn

import (
	"encoding/binary"
	"fmt"
)

// maxCBORDepth bounds nesting so a deeply-nested (or maliciously crafted)
// CBOR item can't blow the stack while we measure its length.
const maxCBORDepth = 16

// cborItemLen returns the number of bytes the first CBOR data item in b
// occupies (RFC 8949). It is the minimum CBOR support webauthn needs: to
// find where the attested credential public key (a COSE_Key map) ends so a
// following extensions map isn't folded into it. It does not interpret
// values — only measures extent — and bounds-checks every read.
//
// Indefinite-length items (additional info 31) are rejected: COSE keys and
// WebAuthn extensions are always definite-length, so an indefinite item
// here signals a malformed frame rather than something to support.
func cborItemLen(b []byte) (int, error) {
	return cborItemLenDepth(b, 0)
}

func cborItemLenDepth(b []byte, depth int) (int, error) {
	if depth > maxCBORDepth {
		return 0, fmt.Errorf("cbor: nesting exceeds %d", maxCBORDepth)
	}
	if len(b) == 0 {
		return 0, fmt.Errorf("cbor: empty input")
	}

	major := b[0] >> 5
	ai := b[0] & 0x1f

	// Resolve the header length and the "argument" (length/count/value)
	// encoded by the additional-info field.
	hdr, arg, err := cborHeader(b, ai)
	if err != nil {
		return 0, err
	}

	switch major {
	case 0, 1, 7: // unsigned int, negative int, simple/float — header carries it all
		return hdr, nil
	case 2, 3: // byte string, text string — header + arg payload bytes
		total, ok := addLen(hdr, arg)
		if !ok || total > len(b) {
			return 0, fmt.Errorf("cbor: string length %d overruns buffer", arg)
		}
		return total, nil
	case 4, 6: // array (arg items) / tag (1 item) — sum nested item lengths
		n := arg
		if major == 6 {
			n = 1
		}
		return sumItems(b, hdr, n, depth)
	case 5: // map — arg pairs => 2*arg items
		two, ok := mul2(arg)
		if !ok {
			return 0, fmt.Errorf("cbor: map pair count %d too large", arg)
		}
		return sumItems(b, hdr, two, depth)
	default:
		return 0, fmt.Errorf("cbor: unsupported major type %d", major)
	}
}

// cborHeader returns the header byte count and the decoded argument for an
// initial byte whose additional-info is ai. Bytes for multi-byte arguments
// are read from b with bounds checks.
func cborHeader(b []byte, ai byte) (hdr int, arg uint64, err error) {
	switch {
	case ai < 24:
		return 1, uint64(ai), nil
	case ai == 24:
		if len(b) < 2 {
			return 0, 0, fmt.Errorf("cbor: truncated 1-byte argument")
		}
		return 2, uint64(b[1]), nil
	case ai == 25:
		if len(b) < 3 {
			return 0, 0, fmt.Errorf("cbor: truncated 2-byte argument")
		}
		return 3, uint64(binary.BigEndian.Uint16(b[1:3])), nil
	case ai == 26:
		if len(b) < 5 {
			return 0, 0, fmt.Errorf("cbor: truncated 4-byte argument")
		}
		return 5, uint64(binary.BigEndian.Uint32(b[1:5])), nil
	case ai == 27:
		if len(b) < 9 {
			return 0, 0, fmt.Errorf("cbor: truncated 8-byte argument")
		}
		return 9, binary.BigEndian.Uint64(b[1:9]), nil
	default: // 28, 29, 30 reserved; 31 indefinite
		return 0, 0, fmt.Errorf("cbor: unsupported additional info %d", ai)
	}
}

// sumItems measures a compound item: its header plus n nested data items.
func sumItems(b []byte, hdr int, n uint64, depth int) (int, error) {
	off := hdr
	for i := uint64(0); i < n; i++ {
		if off >= len(b) {
			return 0, fmt.Errorf("cbor: truncated nested item")
		}
		sub, err := cborItemLenDepth(b[off:], depth+1)
		if err != nil {
			return 0, err
		}
		next, ok := addLen(off, uint64(sub))
		if !ok || next > len(b) {
			return 0, fmt.Errorf("cbor: nested item overruns buffer")
		}
		off = next
	}
	return off, nil
}

// addLen adds a base int and a uint64 length, reporting overflow / negative.
func addLen(base int, n uint64) (int, bool) {
	if n > uint64(^uint(0)>>1) { // exceeds max int
		return 0, false
	}
	sum := base + int(n)
	if sum < base { // overflow
		return 0, false
	}
	return sum, true
}

func mul2(n uint64) (uint64, bool) {
	if n > (^uint64(0))/2 {
		return 0, false
	}
	return n * 2, true
}
