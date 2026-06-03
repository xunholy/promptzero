// SPDX-License-Identifier: AGPL-3.0-or-later

package t2t

// TLV-block decoding for the Type 2 Tag data area.
//
// The data area of a Type 2 Tag (the user memory from page 4 onward, after
// the UID / lock bytes / Capability Container that DecodeDump handles) is a
// sequence of TLV blocks (NFC Forum Type 2 Tag Operation Specification §2.3):
//
//	0x00 NULL          — T only, padding, skipped
//	0x01 Lock Control  — T, L=3, V (reserved dynamic-lock-bit descriptor)
//	0x02 Memory Control— T, L=3, V (reserved memory-area descriptor)
//	0x03 NDEF Message  — T, L, V (the NDEF message; decoded via internal/ndef)
//	0xFD Proprietary   — T, L, V (vendor-specific)
//	0xFE Terminator    — T only, ends the TLV area
//
// The length field is 1 byte for 0x00..0xFE; if that byte is 0xFF, the next
// two bytes are the length, big-endian (the standard NFC 1-or-3-byte form).
// This walker bridges a raw tag-memory dump to ndef_decode: it locates the
// NDEF Message TLV and decodes its value in place, and reports the Lock /
// Memory Control reserved-area descriptors.
//
// Wrap-vs-native: native — fixed TLV framing, reusing the internal/ndef
// walker for the NDEF value. The TLV type values and the 1-or-3-byte length
// encoding are taken from the NFC Forum Type 2 Tag Operation Specification
// (cross-checked against the Nordic nrfxlib Type 2 Tag documentation). The
// Lock / Memory Control 3-byte value sub-structure is vendor-/layout-specific
// and is surfaced raw rather than guessed — no confidently-wrong output.

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ndef"
)

// tlvTypeNames maps the TLV tag byte to its NFC Forum name.
var tlvTypeNames = map[byte]string{
	0x00: "NULL",
	0x01: "Lock Control",
	0x02: "Memory Control",
	0x03: "NDEF Message",
	0xFD: "Proprietary",
	0xFE: "Terminator",
}

// TLVBlock is one decoded TLV block from the Type 2 Tag data area.
type TLVBlock struct {
	Type     string        `json:"type"`
	TypeRaw  int           `json:"type_raw"`
	Offset   int           `json:"offset"`
	Length   int           `json:"length"`
	ValueHex string        `json:"value_hex,omitempty"`
	NDEF     *ndef.Message `json:"ndef,omitempty"`
}

// TLVResult is the decoded TLV-block sequence.
type TLVResult struct {
	Blocks []TLVBlock `json:"blocks"`
	Notes  []string   `json:"notes,omitempty"`
}

// DecodeTLVHex decodes a hex-encoded Type 2 Tag data area (the user memory
// from page 4 onward — use DecodeDump / nfc_t2t for the page 0-3 header).
// ':' / '-' / '_' / whitespace separators are ignored.
func DecodeTLVHex(s string) (*TLVResult, error) {
	cleaned := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(s))
	if cleaned == "" {
		return nil, fmt.Errorf("t2t: empty TLV input")
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return nil, fmt.Errorf("t2t: invalid hex: %w", err)
	}
	return DecodeTLV(b)
}

// DecodeTLV walks the TLV blocks of a Type 2 Tag data area. A length that
// runs past the buffer ends the walk with a note (partial blocks are still
// reported); the NDEF Message TLV's value is decoded via internal/ndef.
func DecodeTLV(b []byte) (*TLVResult, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("t2t: empty TLV input")
	}
	res := &TLVResult{}
	off := 0
	for off < len(b) {
		t := b[off]
		blk := TLVBlock{Type: tlvName(t), TypeRaw: int(t), Offset: off}
		off++

		if t == 0x00 { // NULL — no length/value
			res.Blocks = append(res.Blocks, blk)
			continue
		}
		if t == 0xFE { // Terminator — no length/value, ends the area
			res.Blocks = append(res.Blocks, blk)
			return res, nil
		}

		// All other TLVs carry a length (1 or 3 bytes) + value.
		if off >= len(b) {
			res.Notes = append(res.Notes, fmt.Sprintf("truncated: no length byte for %s TLV at offset %d", blk.Type, blk.Offset))
			res.Blocks = append(res.Blocks, blk)
			return res, nil
		}
		l := int(b[off])
		off++
		if l == 0xFF { // 3-byte length form
			if off+2 > len(b) {
				res.Notes = append(res.Notes, fmt.Sprintf("truncated: incomplete 3-byte length for %s TLV at offset %d", blk.Type, blk.Offset))
				res.Blocks = append(res.Blocks, blk)
				return res, nil
			}
			l = int(b[off])<<8 | int(b[off+1])
			off += 2
		}
		blk.Length = l
		if off+l > len(b) {
			res.Notes = append(res.Notes, fmt.Sprintf("truncated: %s TLV at offset %d declares length %d, only %d bytes remain", blk.Type, blk.Offset, l, len(b)-off))
			res.Blocks = append(res.Blocks, blk)
			return res, nil
		}
		val := b[off : off+l]
		off += l
		blk.ValueHex = strings.ToUpper(hex.EncodeToString(val))

		if t == 0x03 { // NDEF Message — decode in place
			if msg, err := ndef.DecodeBytes(val); err == nil {
				blk.NDEF = &msg
			} else {
				res.Notes = append(res.Notes, fmt.Sprintf("NDEF TLV at offset %d: %v", blk.Offset, err))
			}
		}
		res.Blocks = append(res.Blocks, blk)
	}
	res.Notes = append(res.Notes, "no Terminator (0xFE) TLV found before end of data")
	return res, nil
}

func tlvName(t byte) string {
	if name, ok := tlvTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", t)
}
