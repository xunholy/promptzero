// iso7816.go — host-side ISO/IEC 7816-3 ATR dissector Spec,
// delegating to the internal/iso7816 package for the walker
// proper.
//
// Wrap-vs-native judgement: ISO 7816-3 is a fully public
// standard. The ATR walker is a chain of optional interface
// bytes driven by the high-nibble flags of the preceding TDi.
// Wrapping a FAP for this would add an SD-card install step +
// a firmware-fork dependency for a pure walker. Native delivers
// offline analysis — operators paste an ATR from any PC/SC
// reader output (pcsc_scan, gscriptor, pcscd logs) and
// identify the card type without a card present.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/iso7816"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(iso7816ATRDecodeSpec)
}

var iso7816ATRDecodeSpec = Spec{
	Name: "iso7816_atr_decode",
	Description: "Decode an ISO/IEC 7816-3 Answer To Reset (ATR) string — the response every " +
		"contact smart card sends when reset. Walks the entire ATR structure:\n\n" +
		"- **TS** (Initial Character): direct convention (0x3B) vs inverse convention (0x3F).\n" +
		"- **T0** (Format Character): Y1 interface-byte presence flags + K historical-byte count.\n" +
		"- **Interface-byte chain**: TA / TB / TC / TD bytes for each round, with TDi driving " +
		"the next round's protocol type (T=0 character-oriented, T=1 block-oriented, T=15 " +
		"global parameters) + presence flags. TA1 gets the dedicated decode: clock conversion " +
		"factor Fi (high nibble, ISO 7816-3 Table 7) + work etu factor Di (low nibble, Table 8). " +
		"Used to compute the card's bit rate from the reader clock.\n" +
		"- **Historical bytes** (K bytes): printable-ASCII preview, Category Indicator name " +
		"(0x00 / 0x10 / 0x80 / 0x8x compact-TLV / 0x9x life-cycle).\n" +
		"- **TCK** (Check Character): XOR of all bytes from T0 onwards. Required when any " +
		"non-T=0 protocol is announced; we surface the expected value and a validity flag for " +
		"any caller debugging a TCK mismatch.\n\n" +
		"Pure offline parser — no PC/SC reader required. Useful for identifying EMV chip cards, " +
		"SIM cards (3GPP TS 102.221), Java Cards, ePassports, citizen ID cards, etc. Pairs " +
		"with the existing nfc_emv_decode (which parses the BER-TLV inside EMV READ RECORD " +
		"responses) and nfc_iso14443a_identify (the contactless equivalent of this tool).\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (contact-smart-card decode space — adjacent to " +
		"the EMV BER-TLV walker but covers the cold-start / reset path). Wrap-vs-native: " +
		"native — ISO 7816-3 is a fully public spec, the walker is ~300 lines of bit-twiddling.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded ATR string from a PC/SC reader (e.g. '3B 6E 00 00 80 31 80 66 B0 84 0C 01 6E 01 83 00 90 00' for an EMV card). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   iso7816ATRDecodeHandler,
}

func iso7816ATRDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("iso7816_atr_decode: 'hex' is required")
	}
	res, err := iso7816.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("iso7816_atr_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
