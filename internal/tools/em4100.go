// em4100.go — native host-side decoder for EM4100 (and compatible
// 125 kHz LF "prox card" derivatives) customer IDs.
//
// Wrap-vs-native judgement: EM4100 is a 5-byte customer ID with a
// well-documented public layout. The Flipper firmware's lfrfid_em
// driver renders captured fobs as a 10-hex-char string and we don't
// need any hardware to decompose that into the operator-facing fields
// (decimal serial, the 8-bit version / 32-bit serial split many
// readers print, the 16-bit / 16-bit facility / card split some
// printers use). Wrapping a FAP for this would add an SD-card install
// step + firmware-fork dependency for a 30-line parser. We
// reimplement natively here, gaining host-side analysis (operators
// can decode a serial they wrote on a sticky note without a Flipper
// connected) and inline test coverage against well-known public
// vectors.
//
// Source for the gap: docs/catalog/gap-analysis.md §3 rank 19
// (rfid_pacs_decode — HID Prox / EM4xxx PACS payload decode).
// The HID Prox H10301 side is already covered by wiegand_decode
// (which takes the raw 26-bit Wiegand frame); this Spec handles the
// EM4100 baseline that the Wiegand frame is often a derivative of.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(em4100DecodeSpec)
}

var em4100DecodeSpec = Spec{
	Name: "em4100_decode",
	Description: "Parse a 5-byte EM4100 customer ID into its operator-facing forms — " +
		"the 8-bit version + 32-bit serial split many access-control readers print, the " +
		"16-bit / 16-bit facility / card split some printers use, and zero-padded decimal " +
		"serial (the form on physical card stickers). Pure offline parser — no Flipper " +
		"required. Accepts the hex output of rfid_read or a manually typed customer ID " +
		"from a printed card.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"10 hex characters (the 5-byte EM4100 customer ID). Accepts ':' / '-' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   em4100DecodeHandler,
}

// EM4100Card is the decoded view of a 5-byte EM4100 customer ID. The
// same underlying bytes are exposed in every form an operator might
// be cross-referencing — printed card stickers commonly show the
// zero-padded decimal serial (CardNumberDecimal10), older HID readers
// often print the 8-bit version / 32-bit serial split, and some
// niche manufacturers split the 32-bit serial further as 16/16
// facility / card.
//
// AllZero / AllFF are sentinel flags — many Flipper firmware forks
// emit those values as "no card detected" / "read error" placeholders
// rather than refusing to render. Surfacing them as explicit flags
// keeps callers from confusing a sentinel for a real ID.
type EM4100Card struct {
	HexID               string `json:"hex_id"`
	Bytes               []byte `json:"bytes"`
	VersionByte         uint8  `json:"version_byte"`
	CardNumber          uint32 `json:"card_number"`
	CardNumberDecimal   string `json:"card_number_decimal"`
	CardNumberDecimal10 string `json:"card_number_decimal_10"`
	FacilityCode16      uint16 `json:"facility_code_16"`
	CardNumber16        uint16 `json:"card_number_16"`
	AllZero             bool   `json:"all_zero"`
	AllFF               bool   `json:"all_ff"`
}

// DecodeEM4100 parses a hex string into a structured EM4100Card.
// Accepts common separators (':' '-' whitespace) so the parser
// tolerates rfid_read output, freqman-style colon-separated dumps,
// and operator-supplied hand-typed serials. Returns an error when the
// stripped input isn't exactly 10 hex characters.
//
// Exposed so workflows / future tooling can reuse the parser without
// going through the Spec registry. Mirrors DecodeWiegand's posture.
func DecodeEM4100(raw string) (EM4100Card, error) {
	normalised := normaliseEM4100Hex(raw)
	if len(normalised) != 10 {
		return EM4100Card{}, fmt.Errorf(
			"invalid EM4100 customer ID: want 10 hex characters (5 bytes); got %d",
			len(normalised))
	}
	b, err := hex.DecodeString(normalised)
	if err != nil {
		return EM4100Card{}, fmt.Errorf("invalid EM4100 hex: %w", err)
	}

	card := EM4100Card{
		HexID:       strings.ToUpper(normalised),
		Bytes:       b,
		VersionByte: b[0],
		// Big-endian uint32 over bytes 1-4 — the "32-bit serial" form
		// most HID-style readers print on the card sticker.
		CardNumber:     uint32(b[1])<<24 | uint32(b[2])<<16 | uint32(b[3])<<8 | uint32(b[4]),
		FacilityCode16: uint16(b[1])<<8 | uint16(b[2]),
		CardNumber16:   uint16(b[3])<<8 | uint16(b[4]),
	}
	card.CardNumberDecimal = fmt.Sprintf("%d", card.CardNumber)
	// Zero-pad to 10 digits — the form on printed access-card
	// stickers. 32-bit max (4294967295) is 10 digits, so 10 is the
	// natural pad width.
	card.CardNumberDecimal10 = fmt.Sprintf("%010d", card.CardNumber)

	card.AllZero = true
	card.AllFF = true
	for _, by := range b {
		if by != 0x00 {
			card.AllZero = false
		}
		if by != 0xFF {
			card.AllFF = false
		}
	}

	return card, nil
}

// normaliseEM4100Hex strips the separators operators commonly use
// (whitespace, ':' '-' '_') so the decoder tolerates copy-paste from
// rfid_read output, freqman-style dumps, printed card serials with
// dashes, etc.
func normaliseEM4100Hex(s string) string {
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

func em4100DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("em4100_decode: 'hex' is required")
	}
	card, err := DecodeEM4100(raw)
	if err != nil {
		return "", fmt.Errorf("em4100_decode: %w", err)
	}
	out, _ := json.MarshalIndent(card, "", "  ")
	return string(out), nil
}
