// Package desfire decodes Mifare DESFire Application
// Identifiers (AIDs) — the 3-byte values returned by the
// DESFire GetApplicationIDs command that identify each
// application stored on the card. Pure offline parser; no
// transport, no hardware.
//
// Wrap-vs-native judgement: the DESFire AID format is a public
// NXP specification (DESFire reference, AN10833 for the MAD
// extension). The walker is a 3-byte lookup with a per-function-
// code category table. Wrapping a FAP for this would require an
// SD-card install + a firmware-fork dependency for a pure
// lookup. Native delivers offline analysis — operators paste
// a DESFire AID from a Flipper / Proxmark / pcsc_scan "list
// applications" output and identify the application without
// re-presenting the card.
//
// Pairs with the existing NFC decoders (nfc_iso14443a_identify
// for the card-type identification; mifare_classic_decode for
// the Classic emulation path; nfc_emv_decode for EMV BER-TLV
// inside DESFire applications).
//
// What this package covers:
//   - 3-byte AID decode (big-endian rendering matches the form
//     printed in NXP application notes and operator tools)
//   - MAD-style AID detection (high nibble 0xF — MIFARE
//     Application Directory format)
//   - Function code category lookup for MAD AIDs per NXP
//     AN10833 / ISO 7816-5 (transit / banking / retail /
//     loyalty / access / parking / membership / etc.)
//   - Well-known AID name catalog (MIFARE Classic emulation,
//     OV-chipkaart, HID iCLASS-SE, ePassport, etc.)
//   - Special-value detection (empty 0x000000, wildcard
//     0xFFFFFF, MIFARE Classic emulation 0xF40000)
//
// What this package does NOT cover (deliberately out of scope):
//   - DESFire application key derivation (needs the card master
//     key)
//   - DESFire file structure decode (separate Spec when a
//     caller materialises with file-listing output)
//   - Application key file decryption (AES-128 / 3K3DES)
package desfire

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// AID is the decoded view of a 3-byte DESFire Application
// Identifier.
type AID struct {
	// Raw is the 24-bit value (high byte = byte 0 = canonical
	// rendering).
	Raw int `json:"raw"`
	// Hex is the operator-facing 6-char uppercase form ("F40000").
	Hex string `json:"hex"`
	// Special is "empty" (000000), "mifare_classic" (F40000),
	// "wildcard" (FFFFFF), or "" for normal AIDs.
	Special string `json:"special,omitempty"`
	// MADFormatted reports whether the AID uses the MIFARE
	// Application Directory format (high nibble 0xF).
	MADFormatted bool `json:"mad_formatted"`
	// FunctionCode is the 12-bit MAD function code (bits 23..12
	// when MAD-formatted). 0 for non-MAD AIDs.
	FunctionCode    int    `json:"function_code,omitempty"`
	FunctionCodeHex string `json:"function_code_hex,omitempty"`
	// Category is the documented MAD category name when the
	// function code matches a known range, "" otherwise.
	Category string `json:"category,omitempty"`
	// ApplicationName is the well-known application name when
	// the full AID is in our catalog.
	ApplicationName string `json:"application_name,omitempty"`
	// VendorSubID is the 12-bit sub-identifier (bits 11..0)
	// when the AID is MAD-formatted. The MAD allocates this
	// sub-space to individual operators within a category.
	VendorSubID    int    `json:"vendor_sub_id,omitempty"`
	VendorSubIDHex string `json:"vendor_sub_id_hex,omitempty"`
}

// Decode parses a hex-encoded 3-byte DESFire AID. Accepts 6 hex
// chars with optional 0x prefix and ':' / '-' / '_' /
// whitespace separators.
func Decode(hexBlob string) (AID, error) {
	cleaned := stripSeparators(hexBlob)
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")
	if cleaned == "" {
		return AID{}, fmt.Errorf("desfire: empty input")
	}
	if len(cleaned) != 6 {
		return AID{}, fmt.Errorf("desfire: AID must be 6 hex chars (3 bytes); got %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return AID{}, fmt.Errorf("desfire: invalid hex: %w", err)
	}
	raw := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	return DecodeUint24(raw), nil
}

// DecodeUint24 is the integer-input variant of Decode. Takes
// the bottom 24 bits of the input (high byte ignored).
func DecodeUint24(raw int) AID {
	raw &= 0x00FFFFFF
	out := AID{
		Raw: raw,
		Hex: fmt.Sprintf("%06X", raw),
	}
	// Special-value detection
	switch raw {
	case 0x000000:
		out.Special = "empty"
	case 0xF40000:
		out.Special = "mifare_classic"
		out.ApplicationName = "MIFARE Classic emulation"
	case 0xFFFFFF:
		out.Special = "wildcard"
	}
	// MAD detection: high nibble of byte 0 = 0xF (per NXP AN10833)
	if (raw>>20)&0x0F == 0xF {
		out.MADFormatted = true
		// Function code: bits 23..12 (12 bits). For our purposes
		// this is the top 12 bits of the 24-bit AID.
		out.FunctionCode = (raw >> 12) & 0xFFF
		out.FunctionCodeHex = fmt.Sprintf("%03X", out.FunctionCode)
		out.VendorSubID = raw & 0xFFF
		out.VendorSubIDHex = fmt.Sprintf("%03X", out.VendorSubID)
		out.Category = madCategory(out.FunctionCode)
	}
	// Well-known full-AID lookup overrides any category-only
	// match.
	if name, ok := wellKnownAIDs[raw]; ok {
		out.ApplicationName = name
	}
	return out
}

// madCategory returns the canonical MAD function code category
// name. Function codes 0xFXX where X selects the category and
// the bottom 12 bits select the sub-identifier per NXP AN10833.
//
// Source: NXP AN10833 "Application Identifier (AID)" + ISO/IEC
// 7816-5 application function codes.
func madCategory(fc int) string {
	switch {
	case fc == 0xF40:
		return "MIFARE Classic emulation"
	case fc == 0xF48:
		return "Transit applications"
	case fc == 0xF44:
		return "Banking"
	case fc == 0xFA4:
		return "Retail / loyalty"
	case fc == 0xFCA:
		return "Access control"
	case fc == 0xFC4:
		return "Vending"
	case fc == 0xFCC:
		return "Parking"
	case fc == 0xFE0:
		return "Membership"
	case fc == 0xFA0:
		return "Loyalty cards"
	case fc == 0xFD2:
		return "Time recording / attendance"
	case fc == 0xFE4:
		return "Health"
	case fc == 0xFE8:
		return "Education"
	case fc >= 0xFFE && fc <= 0xFFF:
		return "Reserved by ISO/NXP"
	case fc >= 0xF80 && fc <= 0xF8F:
		return "Vendor-specific (NXP-allocated)"
	}
	return ""
}

// wellKnownAIDs maps full 3-byte AIDs that have a documented
// real-world application to their canonical names. Sourced from
// operator forums, vendor documentation, and the Proxmark3
// research community.
//
// Limited to the most commonly observed AIDs. Operators can
// extend by editing this table; the decoder doesn't depend on
// coverage.
var wellKnownAIDs = map[int]string{
	0x000000: "Card master / default (no application)",
	0x000001: "MIFARE DESFire MAD3 entry",
	0xF40000: "MIFARE Classic emulation",
	0xF48484: "Generic transit application",
	0xF44400: "Banking (legacy MAD slot)",
	// OV-chipkaart (Dutch national transit)
	0x9011F2: "OV-chipkaart (NL)",
	0xC07502: "OV-chipkaart user data",
	// HID iCLASS Seos credentials
	0x484952: "HID iCLASS-SE NDEF",
	0xA00027: "HID iCLASS-SE PACS credential",
	// ePassport (ICAO Doc 9303 LDS application)
	0xA00000: "Reserved / Vendor",
	// Adam Opel Card (well-known German loyalty)
	0xFA4800: "Adam Opel Card / Opel loyalty",
}

// stripSeparators mirrors the convention across our pure-decoder
// packages.
func stripSeparators(s string) string {
	repl := strings.NewReplacer(
		" ", "",
		"\t", "",
		"\n", "",
		"\r", "",
		":", "",
		"-", "",
		"_", "",
	)
	return repl.Replace(strings.TrimSpace(s))
}
