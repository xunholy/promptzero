// jablotron_encode.go — host-side Jablotron LF block generator Spec, the inverse
// of jablotron_decode, delegating to internal/jablotron.Encode.
//
// Wrap-vs-native: native — BCD-encode the card number into five bytes + an
// additive-XOR checksum + the 0xFFFF preamble; stdlib only. Round-trips with
// jablotron_decode. The clone-block generator alongside em4100_encode /
// rfid_pacs_encode / ioprox_encode. Offline transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/jablotron"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(jablotronEncodeSpec)
}

var jablotronEncodeSpec = Spec{
	Name: "jablotron_encode",
	Description: "Generate the 64-bit **Jablotron** LF data block from a printed card number — the inverse of " +
		"`jablotron_decode`, extending the LF clone-generation set (`em4100_encode`, `rfid_pacs_encode`, " +
		"`ioprox_encode`). Jablotron readers/fobs are common across **Czech / Slovak / wider-EU** access control; " +
		"the emitted block is what you would write to a T5577 to clone a Jablotron credential for an authorized " +
		"test.\n\n" +
		"BCD-encodes the card number into the five card-data bytes (two decimal digits per byte — the inverse of " +
		"the decoder's render), then prepends the 0xFFFF preamble and appends the 8-bit checksum (sum of the " +
		"card bytes XOR 0x3A). No confidently-wrong output: the layout + checksum are the same Proxmark3-/" +
		"Flipper-cross-verified ones `jablotron_decode` uses, and the encoder **round-trips** with it (decoding " +
		"the emitted block reproduces the card number) and reproduces the reference vector (card 1234567890 → " +
		"FFFF12345678909E). A card number beyond ten BCD digits is rejected. Generation only — transmits nothing " +
		"and writes to no device, so it is Low risk.\n\n" +
		"Input: **card** (0 - 9999999999, the printed Jablotron card number).\n\n" +
		"Source: docs/catalog/gap-analysis.md (the inverse of jablotron_decode; the Jablotron clone-generation " +
		"half of the LF reader-cloning set). Wrap-vs-native: native — BCD encode + a checksum, stdlib only, no " +
		"new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"card":{"type":"integer","description":"The printed Jablotron card number (0 - 9999999999, up to ten BCD digits)."}
		},
		"required":["card"]
	}`),
	Required:  []string{"card"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   jablotronEncodeHandler,
}

func jablotronEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	v, ok := p["card"]
	if !ok {
		return "", fmt.Errorf("jablotron_encode: 'card' is required")
	}
	f, ok := v.(float64)
	if !ok || f < 0 || f != float64(uint64(f)) {
		return "", fmt.Errorf("jablotron_encode: 'card' must be a non-negative whole number")
	}
	block, err := jablotron.Encode(uint64(f))
	if err != nil {
		return "", fmt.Errorf("jablotron_encode: %w", err)
	}
	out := map[string]any{
		"format":      "Jablotron",
		"card_number": uint64(f),
		"block_hex":   block,
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
