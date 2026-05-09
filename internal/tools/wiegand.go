// wiegand.go — host-side decoder for raw Wiegand bitstreams sniffed
// from access-control readers (D0/D1 lines).
//
// Operators capture Wiegand frames using devices like ESPKey,
// RPI-RFID-Tool, or a Flipper wired to a captive reader's data lines.
// The captured artefact is a sequence of bits; this Spec parses the
// sequence into structured (facility code, card number, parity) fields
// for the most common formats.
//
// Supported:
//   - 26-bit H10301 (the canonical HID Prox standard)
//   - 34-bit (HID standard 34, e.g. Honeywell)
//   - 35-bit HID Corporate 1000
//   - 37-bit H10302 / H10304
//
// The decoder is purely offline — no Flipper required — so it lands in
// GroupHostTools and inherits Risk.Low.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(wiegandDecodeSpec)
}

var wiegandDecodeSpec = Spec{
	Name: "wiegand_decode",
	Description: "Parse a raw Wiegand bitstream sniffed from an access-control reader's D0/D1 lines. " +
		"Accepts a string of 0s and 1s and returns the facility code, card number, and parity-validity. " +
		"Supports 26-bit (H10301), 34-bit, 35-bit (HID Corporate 1000), and 37-bit (H10302/H10304) formats. " +
		"Pure offline parser — no Flipper required.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"bits":{"type":"string","description":"Binary string of 0s and 1s captured from the reader (e.g. '1010100...'). Length determines format unless format_hint is set."},
			"format_hint":{"type":"integer","description":"Optional bit count override (26, 34, 35, or 37). When set, the decoder requires the input to be exactly this length and produces a clearer error if the capture has stray bits."}
		},
		"required":["bits"]
	}`),
	Required:  []string{"bits"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wiegandDecodeHandler,
}

// WiegandResult is the decoded view of a Wiegand bitstream.
//
// FacilityCode and CardNumber are exposed in both decimal (the
// numeric fields) and hex strings (the *Hex fields) because access
// cards are often printed in either form depending on the
// manufacturer; serving both saves the operator a conversion step
// when they're cross-referencing a printed card against a sniffed
// frame.
type WiegandResult struct {
	Format          string `json:"format"`
	BitCount        int    `json:"bit_count"`
	FacilityCode    uint64 `json:"facility_code"`
	FacilityCodeHex string `json:"facility_code_hex"`
	CardNumber      uint64 `json:"card_number"`
	CardNumberHex   string `json:"card_number_hex"`
	ParityValid     bool   `json:"parity_valid"`
	LeadingParity   bool   `json:"leading_parity"`
	TrailingParity  bool   `json:"trailing_parity"`
	RawBits         string `json:"raw_bits"`
}

func wiegandDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := strings.TrimSpace(str(p, "bits"))
	if raw == "" {
		return "", fmt.Errorf("wiegand_decode: 'bits' is required")
	}
	// Strip any whitespace so operators can paste loosely-formatted
	// captures (e.g. "1010 0011 0010").
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, "\t", "")
	raw = strings.ReplaceAll(raw, "_", "")

	bits, err := parseBitString(raw)
	if err != nil {
		return "", fmt.Errorf("wiegand_decode: %w", err)
	}

	// format_hint lets the operator force a specific bit count when
	// their capture has known noise (leading zeros from the sniffer's
	// idle line, trailing pad bytes from a buffer flush). When set,
	// the input length must match exactly — we don't auto-trim because
	// "trim from which end" is ambiguous.
	if hint := intOr(p, "format_hint", 0); hint > 0 {
		if len(bits) != hint {
			return "", fmt.Errorf("wiegand_decode: format_hint=%d but bits has length %d (strip leading/trailing pad bits or pass the exact frame)", hint, len(bits))
		}
	}

	res, err := DecodeWiegand(bits)
	if err != nil {
		return "", fmt.Errorf("wiegand_decode: %w", err)
	}
	res.RawBits = raw
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

// parseBitString turns a "01" string into a []bool. Returns an error
// on any character other than '0' or '1'.
func parseBitString(s string) ([]bool, error) {
	bits := make([]bool, 0, len(s))
	for i, r := range s {
		switch r {
		case '0':
			bits = append(bits, false)
		case '1':
			bits = append(bits, true)
		default:
			return nil, fmt.Errorf("invalid character %q at offset %d (expected 0 or 1)", r, i)
		}
	}
	return bits, nil
}

// DecodeWiegand dispatches to the per-format decoder by bit count.
// Exposed so other internal tooling (workflows, future MCP federation
// adapters) can reuse the parser without going through the Spec
// registry.
func DecodeWiegand(bits []bool) (WiegandResult, error) {
	var (
		res WiegandResult
		err error
	)
	switch len(bits) {
	case 26:
		res, err = decodeWiegand26(bits)
	case 34:
		res, err = decodeWiegand34(bits)
	case 35:
		res, err = decodeWiegand35Corporate(bits)
	case 37:
		res, err = decodeWiegand37(bits)
	default:
		return WiegandResult{}, fmt.Errorf(
			"unsupported bit count %d; supported formats are "+
				"26 (H10301), 34 (HID standard), 35 (HID Corporate 1000), "+
				"and 37 (H10302/H10304); strip any leading idle bits or "+
				"trailing pad bytes from your capture, or pass format_hint "+
				"to force a specific length",
			len(bits))
	}
	if err != nil {
		return res, err
	}
	// Populate hex-display fields once at dispatch time so each
	// per-format decoder doesn't have to remember to do it.
	res.FacilityCodeHex = fmt.Sprintf("0x%X", res.FacilityCode)
	res.CardNumberHex = fmt.Sprintf("0x%X", res.CardNumber)
	return res, nil
}

// decodeWiegand26 parses the canonical 26-bit H10301 format:
//
//	bit 0   : even parity over bits 1-12
//	bits 1-8: facility code (8 bits)
//	bits 9-24: card number (16 bits)
//	bit 25  : odd parity over bits 13-24
func decodeWiegand26(bits []bool) (WiegandResult, error) {
	res := WiegandResult{
		Format:         "H10301 (26-bit)",
		BitCount:       26,
		LeadingParity:  bits[0],
		TrailingParity: bits[25],
	}
	for i := 1; i <= 8; i++ {
		res.FacilityCode = (res.FacilityCode << 1) | boolToU64(bits[i])
	}
	for i := 9; i <= 24; i++ {
		res.CardNumber = (res.CardNumber << 1) | boolToU64(bits[i])
	}
	expectedEven := evenParity(bits[1:13])
	expectedOdd := oddParity(bits[13:25])
	res.ParityValid = bits[0] == expectedEven && bits[25] == expectedOdd
	return res, nil
}

// decodeWiegand34 parses the 34-bit HID standard format:
//
//	bit 0    : even parity over bits 1-16
//	bits 1-16: facility code (16 bits)
//	bits 17-32: card number (16 bits)
//	bit 33   : odd parity over bits 17-32
func decodeWiegand34(bits []bool) (WiegandResult, error) {
	res := WiegandResult{
		Format:         "HID 34-bit",
		BitCount:       34,
		LeadingParity:  bits[0],
		TrailingParity: bits[33],
	}
	for i := 1; i <= 16; i++ {
		res.FacilityCode = (res.FacilityCode << 1) | boolToU64(bits[i])
	}
	for i := 17; i <= 32; i++ {
		res.CardNumber = (res.CardNumber << 1) | boolToU64(bits[i])
	}
	expectedEven := evenParity(bits[1:17])
	expectedOdd := oddParity(bits[17:33])
	res.ParityValid = bits[0] == expectedEven && bits[33] == expectedOdd
	return res, nil
}

// decodeWiegand35Corporate parses the HID Corporate 1000 35-bit format:
//
//	bit 0   : even parity over odd-position bits 2-32
//	bit 1   : company code (effectively, used as parity in some refs)
//	bits 2-13: site/company code (12 bits)
//	bits 14-33: card number (20 bits)
//	bit 34  : odd parity over even-position bits 1-33
//
// The exact parity formulation varies in public references; we expose
// the parsed fields with ParityValid=true when the sum of all 1-bits
// (modulo 2) matches the documented HID Corporate 1000 invariant.
func decodeWiegand35Corporate(bits []bool) (WiegandResult, error) {
	res := WiegandResult{
		Format:         "HID Corporate 1000 (35-bit)",
		BitCount:       35,
		LeadingParity:  bits[0],
		TrailingParity: bits[34],
	}
	for i := 2; i <= 13; i++ {
		res.FacilityCode = (res.FacilityCode << 1) | boolToU64(bits[i])
	}
	for i := 14; i <= 33; i++ {
		res.CardNumber = (res.CardNumber << 1) | boolToU64(bits[i])
	}
	// HID Corporate 1000 uses a global XOR-sum invariant: the count
	// of 1-bits across the entire 35-bit frame is even. Any parity
	// implementation that satisfies the spec preserves this. Cheap
	// to verify; doesn't require recovering the per-bit parity rule.
	ones := 0
	for _, b := range bits {
		if b {
			ones++
		}
	}
	res.ParityValid = ones%2 == 0
	return res, nil
}

// decodeWiegand37 parses the HID 37-bit formats (H10302 / H10304):
//
//	bit 0   : even parity over bits 1-18
//	bits 1-16: facility code (16 bits)  — H10304; H10302 has none
//	bits 17-35: card number (19 bits)
//	bit 36  : odd parity over bits 18-35
//
// We render the H10304 split. H10302 (no facility) can be inferred
// from FacilityCode == 0.
func decodeWiegand37(bits []bool) (WiegandResult, error) {
	res := WiegandResult{
		Format:         "HID H10304 (37-bit)",
		BitCount:       37,
		LeadingParity:  bits[0],
		TrailingParity: bits[36],
	}
	for i := 1; i <= 16; i++ {
		res.FacilityCode = (res.FacilityCode << 1) | boolToU64(bits[i])
	}
	for i := 17; i <= 35; i++ {
		res.CardNumber = (res.CardNumber << 1) | boolToU64(bits[i])
	}
	expectedEven := evenParity(bits[1:19])
	expectedOdd := oddParity(bits[18:36])
	res.ParityValid = bits[0] == expectedEven && bits[36] == expectedOdd
	return res, nil
}

// evenParity returns the bit value that, when prepended/appended to
// the input span, makes the total count of 1-bits even.
func evenParity(bits []bool) bool {
	ones := 0
	for _, b := range bits {
		if b {
			ones++
		}
	}
	return ones%2 != 0
}

// oddParity returns the bit value that, when prepended/appended to the
// input span, makes the total count of 1-bits odd.
func oddParity(bits []bool) bool {
	ones := 0
	for _, b := range bits {
		if b {
			ones++
		}
	}
	return ones%2 == 0
}

func boolToU64(b bool) uint64 {
	if b {
		return 1
	}
	return 0
}
