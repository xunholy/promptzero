// SPDX-License-Identifier: AGPL-3.0-or-later

package emv

import (
	"encoding/hex"
	"fmt"
)

// AFLEntry is one 4-byte entry of an EMV Application File Locator: a short
// file identifier (SFI) and the inclusive record range the terminal must
// READ RECORD from it, plus how many of those records participate in offline
// data authentication (ODA).
type AFLEntry struct {
	SFI         int   `json:"sfi"`
	FirstRecord int   `json:"first_record"`
	LastRecord  int   `json:"last_record"`
	ODARecords  int   `json:"oda_records"`
	Records     []int `json:"records"`
}

// ReadRecord is one implied READ RECORD command (SFI + record number) the
// terminal issues to walk the AFL.
type ReadRecord struct {
	SFI    int `json:"sfi"`
	Record int `json:"record"`
}

// AFL is a decoded EMV Application File Locator (tag 94), returned by the card
// in the GET PROCESSING OPTIONS response. It drives which records the terminal
// reads next.
type AFL struct {
	Entries      []AFLEntry   `json:"entries"`
	ReadRecords  []ReadRecord `json:"read_records"`
	TotalRecords int          `json:"total_records"`
}

// DecodeAFL decodes the raw bytes of an EMV Application File Locator. The AFL
// is a sequence of 4-byte entries — [SFI<<3 | 0][first record][last record]
// [ODA record count] — with no checksum, so correctness is gated structurally:
// the length must be a non-zero multiple of 4, each SFI must be 1-30, the
// record range must be ascending, and the ODA count cannot exceed the range.
// A blob that fails any of these is rejected rather than mis-decoded.
func DecodeAFL(raw []byte) (*AFL, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("emv: empty AFL")
	}
	if len(raw)%4 != 0 {
		return nil, fmt.Errorf("emv: AFL length %d is not a multiple of 4", len(raw))
	}
	out := &AFL{}
	for i := 0; i < len(raw); i += 4 {
		b0, first, last, oda := raw[i], int(raw[i+1]), int(raw[i+2]), int(raw[i+3])
		if b0&0x07 != 0 {
			return nil, fmt.Errorf("emv: AFL entry %d: low 3 bits of SFI byte must be 0 (got 0x%02X)", i/4, b0)
		}
		sfi := int(b0 >> 3)
		if sfi < 1 || sfi > 30 {
			return nil, fmt.Errorf("emv: AFL entry %d: SFI %d out of range 1-30", i/4, sfi)
		}
		if first < 1 {
			return nil, fmt.Errorf("emv: AFL entry %d: first record %d < 1", i/4, first)
		}
		if last < first {
			return nil, fmt.Errorf("emv: AFL entry %d: last record %d < first record %d", i/4, last, first)
		}
		if oda > last-first+1 {
			return nil, fmt.Errorf("emv: AFL entry %d: ODA record count %d exceeds range %d", i/4, oda, last-first+1)
		}
		recs := make([]int, 0, last-first+1)
		for r := first; r <= last; r++ {
			recs = append(recs, r)
			out.ReadRecords = append(out.ReadRecords, ReadRecord{SFI: sfi, Record: r})
		}
		out.Entries = append(out.Entries, AFLEntry{
			SFI:         sfi,
			FirstRecord: first,
			LastRecord:  last,
			ODARecords:  oda,
			Records:     recs,
		})
		out.TotalRecords += len(recs)
	}
	return out, nil
}

// DecodeAFLHex is the hex-string convenience wrapper.
func DecodeAFLHex(s string) (*AFL, error) {
	b, err := hex.DecodeString(stripSeparators(s))
	if err != nil {
		return nil, fmt.Errorf("emv: invalid hex: %w", err)
	}
	return DecodeAFL(b)
}
