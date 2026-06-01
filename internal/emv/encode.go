// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import "fmt"

// Encode serialises a list of TLVs back into EMV BER-TLV bytes — the inverse
// of ParseBytes. For each TLV it emits the tag bytes, the definite length
// (minimal short/long form), and the value. Whether a tag is constructed is
// taken from its own P/C bit (0x20 of the first tag byte), exactly as Parse
// reads it: constructed tags are rebuilt from Children, primitive tags from
// Value. So Encode(Parse(x)) reproduces a minimally-encoded x.
//
// # Wrap-vs-native judgement
//
// Native, and the inverse of the existing parser. EMV BER-TLV is a fully
// public, deterministic structure (ISO/IEC 8825-1 BER + EMV Book 3); encoding
// is pure tag/length/value byte assembly — no crypto, no hardware. It builds
// the TLV blobs an operator sends to a card (PDOL/GPO/command data) or stages
// for a response; generation only, no card I/O. Correctness is verifiable two
// ways: round-trip against ParseBytes and hand-computed TLV bytes.
func Encode(tlvs []TLV) ([]byte, error) {
	var out []byte
	for i := range tlvs {
		enc, err := encodeOne(tlvs[i])
		if err != nil {
			return nil, err
		}
		out = append(out, enc...)
	}
	return out, nil
}

func encodeOne(t TLV) ([]byte, error) {
	if t.Tag == 0 {
		return nil, fmt.Errorf("emv: TLV tag is zero")
	}
	tagBytes := tagToBytes(t.Tag)
	var value []byte
	if tagBytes[0]&0x20 != 0 {
		// Constructed: rebuild from children (a constructed tag with no
		// children but raw Value bytes passes the value through verbatim).
		if len(t.Children) > 0 {
			for i := range t.Children {
				e, err := encodeOne(t.Children[i])
				if err != nil {
					return nil, err
				}
				value = append(value, e...)
			}
		} else {
			value = t.Value
		}
	} else {
		value = t.Value
	}
	out := append([]byte{}, tagBytes...)
	out = append(out, encodeLength(len(value))...)
	out = append(out, value...)
	return out, nil
}

// tagToBytes renders a packed tag uint32 back to its big-endian byte form —
// the exact inverse of readTag's packing, matching formatTag's width tiers.
func tagToBytes(tag uint32) []byte {
	switch {
	case tag <= 0xFF:
		return []byte{byte(tag)}
	case tag <= 0xFFFF:
		return []byte{byte(tag >> 8), byte(tag)}
	case tag <= 0xFFFFFF:
		return []byte{byte(tag >> 16), byte(tag >> 8), byte(tag)}
	default:
		return []byte{byte(tag >> 24), byte(tag >> 16), byte(tag >> 8), byte(tag)}
	}
}

// encodeLength renders a BER definite length: short form (< 0x80) in one
// byte, otherwise long form (0x80|n followed by n minimal big-endian bytes).
// The inverse of readLength.
func encodeLength(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var lb []byte
	for v := n; v > 0; v >>= 8 {
		lb = append([]byte{byte(v)}, lb...)
	}
	return append([]byte{0x80 | byte(len(lb))}, lb...)
}
