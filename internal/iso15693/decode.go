// SPDX-License-Identifier: AGPL-3.0-or-later

// Package iso15693 decodes the identity fields of an ISO/IEC 15693 vicinity
// card (HF 13.56 MHz) — the UID and, optionally, the AFI application-family
// byte. It is the second major HF standard alongside ISO 14443 (this project's
// internal/iso14443a), seen on library, access-control, medical, laundry and
// industrial tags (NXP ICODE, TI Tag-it, ST LRI). Offline read of an
// operator-supplied UID dump; no hardware.
//
// # Wrap-vs-native judgement
//
// Native. The UID is a fixed 8-byte structure (ISO 15693-3 §6.1) and the AFI is
// a documented nibble table — a few lines of byte parsing plus a reuse of the
// ISO 7816-6 IC-manufacturer table already maintained in internal/iso14443a.
//
// # Verifiable / no confidently-wrong output
//
// The UID's most-significant byte is fixed at 0xE0 for every ISO 15693 tag —
// the hard anchor: a UID that doesn't start 0xE0 is reported as non-standard
// rather than mis-decoded. The manufacturer byte is looked up in the shared,
// in-tree-verified ISO 7816-6 table (unknown codes surfaced raw, never
// guessed), and the AFI family is the documented ISO 15693-3 Table.
//
// # Covered / deferred
//
// Covered: UID (prefix validation, IC-manufacturer, serial) and the AFI
// application family. Deferred: the DSFID (Data Storage Format ID — largely
// manufacturer/application-specific, no portable meaning) and the full
// Get-System-Information response framing (flag-gated fields — held back until
// gated against a confidently-sourced reference).
package iso15693

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iso14443a"
)

// UID is a decoded ISO 15693 unique identifier.
type UID struct {
	Raw              string   `json:"raw"`               // 8 bytes, MSB-first hex
	PrefixValid      bool     `json:"prefix_valid"`      // MSB == 0xE0
	ManufacturerCode string   `json:"manufacturer_code"` // hex of the IC manufacturer byte
	Manufacturer     string   `json:"manufacturer,omitempty"`
	Serial           string   `json:"serial"` // the 6 IC-serial bytes, hex
	AFI              *AFI     `json:"afi,omitempty"`
	Notes            []string `json:"notes,omitempty"`
}

// AFI is a decoded Application Family Identifier (ISO 15693-3 §10).
type AFI struct {
	Raw    string `json:"raw"`
	Family string `json:"family"`
}

// afiFamilies maps the AFI high nibble to its application family. The low nibble
// is a sub-family (application-specific); 0x00 means "all families".
var afiFamilies = map[byte]string{
	0x0: "all families",
	0x1: "transport",
	0x2: "financial",
	0x3: "identification",
	0x4: "telecommunication",
	0x5: "medical",
	0x6: "multimedia",
	0x7: "gaming",
	0x8: "data storage",
	0x9: "item management",
	0xA: "express parcels",
	0xB: "postal services",
	0xC: "airline bags",
}

// DecodeUID decodes an 8-byte ISO 15693 UID given as MSB-first hex. The UID is
// stored/displayed E0 <manufacturer> <6-byte serial>.
func DecodeUID(uidHex string) (*UID, error) {
	clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(strings.TrimSpace(uidHex))
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("iso15693: UID is not valid hex: %w", err)
	}
	if len(b) != 8 {
		return nil, fmt.Errorf("iso15693: UID must be 8 bytes (got %d)", len(b))
	}
	u := &UID{
		Raw:              strings.ToUpper(hex.EncodeToString(b)),
		PrefixValid:      b[0] == 0xE0,
		ManufacturerCode: fmt.Sprintf("%02X", b[1]),
		Serial:           strings.ToUpper(hex.EncodeToString(b[2:])),
	}
	if !u.PrefixValid {
		u.Notes = append(u.Notes, fmt.Sprintf("MSB is 0x%02X, not 0xE0 — not a standard ISO 15693 UID (byte order may be reversed, or not an ISO 15693 tag)", b[0]))
	}
	if name, ok := iso14443a.ManufacturerName(b[1]); ok {
		u.Manufacturer = name
	} else {
		u.Notes = append(u.Notes, "IC manufacturer code not in the ISO 7816-6 table (surfaced raw)")
	}
	return u, nil
}

// DecodeAFI decodes a single AFI byte.
func DecodeAFI(afi byte) *AFI {
	fam, ok := afiFamilies[afi>>4]
	if !ok {
		fam = "proprietary / RFU"
	}
	return &AFI{Raw: fmt.Sprintf("%02X", afi), Family: fam}
}
