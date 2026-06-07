// noralsy_encode.go — host-side Noralsy LF block generator Spec, the inverse of
// noralsy_decode, delegating to internal/noralsy.Encode.
//
// Wrap-vs-native: native — BCD-encode the card + year, place them
// non-contiguously, compute the two nibble checksums + the 0xBB0214FF preamble;
// stdlib only. Round-trips with noralsy_decode. The clone-block generator
// completing the LF set (em4100/pacs/ioprox/jablotron/viking encoders). Offline
// transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/noralsy"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(noralsyEncodeSpec)
}

var noralsyEncodeSpec = Spec{
	Name: "noralsy_encode",
	Description: "Generate the 96-bit **Noralsy** LF data block from a printed card number and year — the " +
		"inverse of `noralsy_decode`, completing the LF clone-generation set (`em4100_encode`, " +
		"`rfid_pacs_encode`, `ioprox_encode`, `jablotron_encode`, `viking_encode`). Noralsy readers/fobs are " +
		"common in **French / wider-EU** residential access control; the emitted block is what you would write " +
		"to a T5577 to clone a Noralsy credential for an authorized test.\n\n" +
		"BCD-encodes the card number into the 28-bit packed field (placed non-contiguously per the layout), " +
		"BCD-encodes the year, writes the 0xBB0214FF preamble, and computes the two 4-bit nibble checksums (chk1 " +
		"over bits 32-71, chk2 over bits 0-75). No confidently-wrong output: the layout, the (non-contiguous) " +
		"packing, the year field and the two checksums are the same Proxmark3-/Flipper-cross-verified ones " +
		"`noralsy_decode` uses, and the encoder **round-trips** with it (decoding the emitted block reproduces " +
		"the card number + year with both checksums valid) and reproduces the reference vector (card 1234567 / " +
		"year 2021 → BB0214FF1232104567370000). A card number beyond 7 BCD digits, or a year outside the " +
		"round-trippable 1961-2060 window (the decoder's >60 century heuristic boundary), is rejected. Generation " +
		"only — transmits nothing and writes to no device, so it is Low risk.\n\n" +
		"Inputs: **card** (0 - 9999999, the printed Noralsy card number) and **year** (1961 - 2060).\n\n" +
		"Source: docs/catalog/gap-analysis.md (the inverse of noralsy_decode; completes the LF clone-generation " +
		"set). Wrap-vs-native: native — BCD encode + non-contiguous placement + two nibble checksums, stdlib " +
		"only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"card":{"type":"integer","description":"The printed Noralsy card number (0 - 9999999, up to 7 BCD digits)."},
			"year":{"type":"integer","description":"The manufacture year (1961 - 2060, the round-trippable window)."}
		},
		"required":["card","year"]
	}`),
	Required:  []string{"card", "year"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   noralsyEncodeHandler,
}

func noralsyEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	card, err := intField(p, "card", 0, 9999999)
	if err != nil {
		return "", fmt.Errorf("noralsy_encode: %w", err)
	}
	year, err := intField(p, "year", 1961, 2060)
	if err != nil {
		return "", fmt.Errorf("noralsy_encode: %w", err)
	}
	block, err := noralsy.Encode(uint64(card), year)
	if err != nil {
		return "", fmt.Errorf("noralsy_encode: %w", err)
	}
	out := map[string]any{
		"format":      "Noralsy",
		"card_number": card,
		"year":        year,
		"block_hex":   block,
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
