// Package jtag decodes JTAG IDCODE values (IEEE 1149.1) and the
// SWD DPIDR / TARGETID variants used by ARM CoreSight debug
// interfaces. Pure offline parser; no transport, no hardware.
//
// Wrap-vs-native judgement: IEEE 1149.1 IDCODE is a fully
// public spec, JEDEC JEP106 (manufacturer code registry) is
// also public. The walker is bit-level decoding over a 32-bit
// value with a lookup table. Wrapping a FAP for this would
// require an SD-card install + a firmware-fork dependency for a
// pure lookup. Native delivers offline analysis — operators
// scan a JTAG chain with their Bus Pirate / openocd /
// adapter-of-choice, read the IDCODE, and identify the chip
// without touching the board again.
//
// Pairs with the existing Bus Pirate / hw_recon workflows.
//
// What this package covers:
//   - IDCODE bit walker: fixed bit 0 (must be 1 per IEEE 1149.1)
//   - 11-bit JEDEC JEP106 manufacturer code + 16-bit part
//     number + 4-bit version
//   - JEDEC JEP106 manufacturer-code lookup (~120 vendors —
//     the ones that ship chips with documented JTAG IDs)
//   - Per-vendor part-number lookup for the most common chip
//     families (STMicro STM32 / Atmel-Microchip AVR / NXP
//     Kinetis + i.MX / TI MSP430 + Stellaris / Cypress /
//     Infineon)
//   - SWD DPIDR variants: same 32-bit shape but bit 0 is the
//     "DP version" indicator (ARM DAP), and TARGETID uses the
//     same JEP106 + part-number split — we surface both
//     interpretations when the operator's source matches.
//
// What this package does NOT cover (deliberately out of scope):
//   - Boundary-scan instruction decode (IDCODE / BYPASS /
//     SAMPLE / EXTEST / etc.) — that's the post-identification
//     step
//   - SWD memory-mapped register decode (MEM-AP / DRW / etc.)
//   - Driving an adapter to perform the scan
package jtag

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// IDCode is the decoded view of a 32-bit IDCODE value.
type IDCode struct {
	// Raw is the full 32-bit value.
	Raw uint32 `json:"raw"`
	// Hex is the operator-facing 8-character form ("4BA00477").
	Hex string `json:"hex"`
	// FixedBit is bit 0 (must be 1 per IEEE 1149.1). Surfaced
	// so callers can flag malformed inputs.
	FixedBit      int  `json:"fixed_bit"`
	FixedBitValid bool `json:"fixed_bit_valid"`
	// ManufacturerID is the 11-bit JEDEC JEP106 manufacturer
	// code (bits 11..1).
	ManufacturerID  int    `json:"manufacturer_id"`
	ManufacturerHex string `json:"manufacturer_hex"`
	// ManufacturerName is the JEP106 vendor name when in our
	// table, empty otherwise.
	ManufacturerName string `json:"manufacturer_name,omitempty"`
	// PartNumber is the 16-bit vendor-specific part number
	// (bits 27..12).
	PartNumber    int    `json:"part_number"`
	PartNumberHex string `json:"part_number_hex"`
	// PartName is the vendor-specific chip name when in our
	// table, empty otherwise.
	PartName string `json:"part_name,omitempty"`
	// Version is the 4-bit revision (bits 31..28).
	Version int `json:"version"`
}

// Decode parses a hex-encoded IDCODE. Accepts 8 hex chars
// (32 bits) with optional 0x prefix and ':' / '-' / '_' /
// whitespace separators.
func Decode(hexBlob string) (IDCode, error) {
	cleaned := stripSeparators(hexBlob)
	cleaned = strings.TrimPrefix(strings.ToLower(cleaned), "0x")
	if cleaned == "" {
		return IDCode{}, fmt.Errorf("jtag: empty input")
	}
	if len(cleaned) != 8 {
		return IDCode{}, fmt.Errorf("jtag: IDCODE must be 8 hex chars (32 bits); got %d", len(cleaned))
	}
	b, err := hex.DecodeString(cleaned)
	if err != nil {
		return IDCode{}, fmt.Errorf("jtag: invalid hex: %w", err)
	}
	raw := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return DecodeUint32(raw), nil
}

// DecodeUint32 is the integer-input variant of Decode.
func DecodeUint32(raw uint32) IDCode {
	fixed := int(raw & 1)
	manuf := int((raw >> 1) & 0x7FF)
	part := int((raw >> 12) & 0xFFFF)
	ver := int((raw >> 28) & 0x0F)
	out := IDCode{
		Raw:             raw,
		Hex:             fmt.Sprintf("%08X", raw),
		FixedBit:        fixed,
		FixedBitValid:   fixed == 1,
		ManufacturerID:  manuf,
		ManufacturerHex: fmt.Sprintf("%03X", manuf),
		PartNumber:      part,
		PartNumberHex:   fmt.Sprintf("%04X", part),
		Version:         ver,
	}
	if name, ok := jep106[uint16(manuf)]; ok {
		out.ManufacturerName = name
	}
	if vendorParts, ok := partNames[uint16(manuf)]; ok {
		if pn, ok := vendorParts[uint16(part)]; ok {
			out.PartName = pn
		}
	}
	return out
}

// stripSeparators mirrors the convention in our other
// pure-decoder packages.
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
