// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"fmt"
)

// DOLEntry is one (tag, length) request inside an EMV Data Object List. A DOL
// carries no values — only the tags the card asks the terminal to supply and
// how many bytes each must occupy.
type DOLEntry struct {
	Tag    uint32 `json:"tag"`
	TagHex string `json:"tag_hex"`
	Name   string `json:"name,omitempty"`
	Length int    `json:"length"`
}

// DOL is a decoded EMV Data Object List — PDOL (tag 9F38), CDOL1/CDOL2 (8C /
// 8D), DDOL (9F49), or TDOL (97). TotalLength is the size of the concatenated
// value field the terminal must build and hand back (e.g. the GPO command
// data assembled from a PDOL).
type DOL struct {
	Entries     []DOLEntry `json:"entries"`
	Count       int        `json:"count"`
	TotalLength int        `json:"total_length"`
}

// DecodeDOL decodes the raw bytes of an EMV Data Object List: a concatenation
// of (BER tag, BER length) pairs with NO value bytes between them. This is why
// the BER-TLV walker can't parse a DOL — there are no values to walk — and why
// tag 9F38/8C/8D's value is left raw. Tag names are resolved from the same
// curated table the TLV walker uses; the parse is purely structural (tag +
// length header bytes) so there is nothing to mis-decode.
func DecodeDOL(raw []byte) (*DOL, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("emv: empty DOL")
	}
	var entries []DOLEntry
	total := 0
	off := 0
	for off < len(raw) {
		tag, tagLen, _, err := readTag(raw[off:])
		if err != nil {
			return nil, fmt.Errorf("emv: DOL at offset %d: %w", off, err)
		}
		if off+tagLen >= len(raw) {
			return nil, fmt.Errorf("emv: DOL entry %s has no length byte", formatTag(tag))
		}
		length, lenLen, err := readLength(raw[off+tagLen:])
		if err != nil {
			return nil, fmt.Errorf("emv: DOL length for %s: %w", formatTag(tag), err)
		}
		entries = append(entries, DOLEntry{
			Tag:    tag,
			TagHex: formatTag(tag),
			Name:   TagName(tag),
			Length: length,
		})
		total += length
		off += tagLen + lenLen // DOLs carry no value bytes — advance past the header only
	}
	return &DOL{Entries: entries, Count: len(entries), TotalLength: total}, nil
}

// DecodeDOLHex is the hex-string convenience wrapper.
func DecodeDOLHex(s string) (*DOL, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeDOL(b)
}

// IsDOLTag reports whether tag is one of the EMV Data Object List tags
// (PDOL / CDOL1 / CDOL2 / DDOL / TDOL).
func IsDOLTag(tag uint32) bool {
	switch tag {
	case 0x9F38, 0x8C, 0x8D, 0x9F49, 0x97:
		return true
	default:
		return false
	}
}
