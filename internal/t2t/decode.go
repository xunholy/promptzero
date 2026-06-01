// SPDX-License-Identifier: AGPL-3.0-or-later

// Package t2t decodes the NFC Forum Type 2 Tag structure — the page layout
// shared by NXP NTAG21x and MIFARE Ultralight, by far the most common NFC
// tags (transit, access fobs, amiibo, marketing tags). It interprets a
// page-aligned memory dump's header: the 7-byte UID with its BCC check
// bytes, the static lock bytes, and the Capability Container.
//
// # Wrap-vs-native judgement
//
// Native. The Type 2 Tag layout is a public NFC Forum standard (Type 2 Tag
// Operation Specification) reproduced in every NTAG/Ultralight datasheet
// and in libnfc / the Flipper NFC stack: pages are 4 bytes, page 0-2 hold
// the 7-byte UID + BCC0/BCC1 + internal + static lock bytes, and page 3 is
// the Capability Container. Decoding is a fixed-offset read with a
// hand-computable XOR checksum (the BCC bytes) — no crypto, no hardware,
// no card present at decode time (the operator pastes a dump from
// nfc_mfu_rdbl / a Flipper .nfc / libnfc). It is distinct from the
// mifare package (MIFARE Classic) and from ndef (the NDEF message inside
// the user pages): this is the tag-structure layer.
//
// # Verifiable
//
// The UID carries two XOR check bytes that gate correctness without a card:
//
//	BCC0 = 0x88 (cascade tag) XOR UID0 XOR UID1 XOR UID2   (page 0, byte 3)
//	BCC1 = UID3 XOR UID4 XOR UID5 XOR UID6                 (page 2, byte 0)
//
// Both are validated and surfaced; a mismatch is flagged (a misread, or a
// non-7-byte-UID tag) rather than silently trusted.
//
// # Deliberately deferred
//
// The per-variant configuration pages (AUTH0 / ACCESS / PWD / PACK), whose
// PAGE LOCATION differs between NTAG213/215/216 and the Ultralight EV1
// variants, are NOT interpreted — guessing the variant to locate them would
// risk a confidently-wrong reading; the size hint from the Capability
// Container is surfaced instead. The NDEF message in the user pages is
// decoded by ndef_decode.
package t2t

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// CascadeTag is the 0x88 prefix XORed into BCC0 for a double-size (7-byte)
// UID.
const CascadeTag = 0x88

// CapabilityContainer is the decoded view of page 3.
type CapabilityContainer struct {
	Hex         string `json:"hex"`
	MagicValid  bool   `json:"magic_valid"` // CC0 == 0xE1 (NDEF-formatted)
	Version     string `json:"version"`     // e.g. "1.0"
	SizeBytes   int    `json:"size_bytes"`  // CC2 * 8
	ReadAccess  string `json:"read_access"`
	WriteAccess string `json:"write_access"`
}

// T2T is the decoded Type 2 Tag structure.
type T2T struct {
	Pages       int                 `json:"pages"`
	UID         string              `json:"uid"`  // 7-byte UID, hex
	BCC0        string              `json:"bcc0"` // captured page0[3]
	BCC0Valid   bool                `json:"bcc0_valid"`
	BCC1        string              `json:"bcc1"` // captured page2[0]
	BCC1Valid   bool                `json:"bcc1_valid"`
	Internal    string              `json:"internal"`   // page2[1]
	LockBytes   string              `json:"lock_bytes"` // page2[2..3]
	LockedPages []int               `json:"locked_pages"`
	BlockLocks  []string            `json:"block_locking,omitempty"`
	CC          CapabilityContainer `json:"capability_container"`
	Notes       []string            `json:"notes,omitempty"`
}

// Decode parses a hex-encoded Type 2 Tag memory dump. At least the first 4
// pages (16 bytes) are required. Separators and a 0x prefix are tolerated.
func Decode(hexStr string) (*T2T, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "", "\n", "", "\t", "").Replace(strings.TrimSpace(hexStr))
	if strings.HasPrefix(strings.ToLower(clean), "0x") {
		clean = clean[2:]
	}
	if clean == "" {
		return nil, fmt.Errorf("t2t: empty input")
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("t2t: invalid hex: %w", err)
	}
	if len(b) < 16 {
		return nil, fmt.Errorf("t2t: need at least 4 pages (16 bytes); got %d", len(b))
	}

	out := &T2T{Pages: len(b) / 4}
	uid := []byte{b[0], b[1], b[2], b[4], b[5], b[6], b[7]}
	out.UID = strings.ToUpper(hex.EncodeToString(uid))

	bcc0 := b[3]
	expBCC0 := byte(CascadeTag) ^ b[0] ^ b[1] ^ b[2]
	out.BCC0 = fmt.Sprintf("%02X", bcc0)
	out.BCC0Valid = bcc0 == expBCC0

	bcc1 := b[8]
	expBCC1 := b[4] ^ b[5] ^ b[6] ^ b[7]
	out.BCC1 = fmt.Sprintf("%02X", bcc1)
	out.BCC1Valid = bcc1 == expBCC1
	if !out.BCC0Valid || !out.BCC1Valid {
		out.Notes = append(out.Notes,
			"BCC mismatch — a misread dump, or not a standard 7-byte-UID Type 2 tag (UID/fields shown unverified)")
	}

	out.Internal = fmt.Sprintf("%02X", b[9])
	lock0, lock1 := b[10], b[11]
	out.LockBytes = fmt.Sprintf("%02X%02X", lock0, lock1)
	out.LockedPages, out.BlockLocks = decodeStaticLocks(lock0, lock1)

	out.CC = decodeCC(b[12:16])
	return out, nil
}

// decodeStaticLocks decodes the page-2 static lock bytes per the NFC Forum
// Type 2 / NXP MF0ICU1 mapping. Lock byte 0 bits 3..7 lock pages 3..7; its
// bits 0..2 are the block-locking bits; lock byte 1 bits 0..7 lock pages
// 8..15.
func decodeStaticLocks(lock0, lock1 byte) (locked []int, blockLocks []string) {
	for bit := 3; bit <= 7; bit++ {
		if lock0&(1<<uint(bit)) != 0 {
			locked = append(locked, bit) // bit n locks page n for n in 3..7
		}
	}
	for bit := 0; bit <= 7; bit++ {
		if lock1&(1<<uint(bit)) != 0 {
			locked = append(locked, 8+bit) // page 8..15
		}
	}
	blNames := []string{"BL pages 10-15", "BL pages 4-9", "BL CC (page 3)"}
	for bit := 0; bit <= 2; bit++ {
		if lock0&(1<<uint(bit)) != 0 {
			blockLocks = append(blockLocks, blNames[bit])
		}
	}
	return locked, blockLocks
}

// decodeCC decodes the 4-byte Capability Container at page 3.
func decodeCC(cc []byte) CapabilityContainer {
	out := CapabilityContainer{
		Hex:        strings.ToUpper(hex.EncodeToString(cc)),
		MagicValid: cc[0] == 0xE1,
		Version:    fmt.Sprintf("%d.%d", cc[1]>>4, cc[1]&0x0F),
		SizeBytes:  int(cc[2]) * 8,
	}
	out.ReadAccess = ccAccessName(cc[3] >> 4)
	out.WriteAccess = ccAccessName(cc[3] & 0x0F)
	return out
}

func ccAccessName(n byte) string {
	switch n {
	case 0x0:
		return "granted (no security)"
	case 0xF:
		return "no access"
	default:
		return fmt.Sprintf("proprietary (0x%X)", n)
	}
}
