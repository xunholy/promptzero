// pacs_encode.go — host-side HID Prox PACS payload encoder Spec, the
// inverse of rfid_pacs_decode, delegating to internal/pacs.EncodeWiegand.
//
// Wrap-vs-native: native — HID Wiegand formats are public fixed-width
// bit layouts with parity; generation is pure bit-twiddling. The output is
// round-trip-verified against the existing rfid_pacs_decode walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/pacs"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(rfidPACSEncodeSpec)
}

var rfidPACSEncodeSpec = Spec{
	Name: "rfid_pacs_encode",
	Description: "Build the raw Wiegand bit-stream for an HID Prox credential from a facility code " +
		"+ card number — the offline inverse of rfid_pacs_decode. Produces the exact frame a reader " +
		"emits (leading even parity, binary FC + CN fields, trailing odd parity, MSB-first), ready to " +
		"clone onto a T5577 / emulate as a known credential in a reader-cloning workflow. Generation " +
		"only — it writes nothing and transmits nothing; pair the bits with rfid_write / an emulate " +
		"stage.\n\n" +
		"Supported formats (clean parity, round-trip-verified against the decoder):\n" +
		" - **H10301** (26-bit) — even parity + 8-bit facility code (0-255) + 16-bit card number " +
		"(0-65535) + odd parity.\n" +
		" - **H10306** (34-bit) — even parity + 16-bit facility code (0-65535) + 16-bit card number " +
		"(0-65535) + odd parity.\n" +
		" - **H10304** (37-bit) — even parity + 16-bit facility code (0-65535) + 19-bit card number " +
		"(0-524287) + odd parity (even over the top 18 data bits, odd over the bottom 18).\n" +
		" - **H10302** (37-bit, no facility code) — even parity + 35-bit card number (0-34359738367) + " +
		"odd parity; pass facility_code 0.\n\n" +
		"Out of scope (deferred): the HID Corporate 1000 (35/48-bit) formats — their parity is " +
		"self-referential / proprietary (the parity bits fall inside their own coverage range), so " +
		"encoding to a guaranteed-valid frame is not reliable without an external reference vector " +
		"(rfid_pacs_decode still surfaces them as candidates).\n\n" +
		"Output is the bit-string plus the frame decoded back from it for confirmation — round-trip-" +
		"verified against rfid_pacs_decode. Companion to rfid_pacs_decode (gap-analysis §3 rank 19). " +
		"Wrap-vs-native: native — public fixed-width layouts, pure bit + parity maths, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"format":{"type":"string","description":"HID format: H10301 (26-bit), H10306 (34-bit), H10304 (37-bit), or H10302 (37-bit, no FC)."},
			"facility_code":{"type":"integer","description":"Facility code (H10301: 0-255; H10306/H10304: 0-65535; H10302: must be 0)."},
			"card_number":{"type":"integer","description":"Card number (H10301/H10306: 0-65535; H10304: 0-524287; H10302: 0-34359738367)."}
		},
		"required":["format","facility_code","card_number"]
	}`),
	Required:  []string{"format", "facility_code", "card_number"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rfidPACSEncodeHandler,
}

func rfidPACSEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	format := str(p, "format")
	if format == "" {
		return "", fmt.Errorf("rfid_pacs_encode: 'format' is required (H10301, H10306, H10304, or H10302)")
	}
	fc, ok := intArg(p["facility_code"])
	if !ok || fc < 0 {
		return "", fmt.Errorf("rfid_pacs_encode: 'facility_code' is required and must be a non-negative integer")
	}
	cn, ok := intArg(p["card_number"])
	if !ok || cn < 0 {
		return "", fmt.Errorf("rfid_pacs_encode: 'card_number' is required and must be a non-negative integer")
	}

	bits, err := pacs.EncodeWiegand(format, uint64(fc), uint64(cn))
	if err != nil {
		return "", fmt.Errorf("rfid_pacs_encode: %w", err)
	}
	frame, _ := pacs.DecodeBits(bits)
	out, _ := json.MarshalIndent(struct {
		Bits  string       `json:"bits"`
		Frame *pacs.Result `json:"decoded_back"`
	}{Bits: bits, Frame: frame}, "", "  ")
	return string(out), nil
}
