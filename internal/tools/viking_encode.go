// viking_encode.go — host-side Viking LF block generator Spec, the inverse of
// viking_decode, delegating to internal/viking.Encode.
//
// Wrap-vs-native: native — place the 32-bit card ID + the 0xF20000 preamble +
// an XOR checksum; stdlib only. Round-trips with viking_decode. The clone-block
// generator alongside em4100_encode / rfid_pacs_encode / ioprox_encode /
// jablotron_encode. Offline transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/viking"
)

func init() { //nolint:gochecknoinits
	Register(vikingEncodeSpec)
}

var vikingEncodeSpec = Spec{
	Name: "viking_encode",
	Description: "Generate the 64-bit **Viking** ('Viking Acs') LF data block from a 32-bit card ID — the " +
		"inverse of `viking_decode`, extending the LF clone-generation set (`em4100_encode`, `rfid_pacs_encode`, " +
		"`ioprox_encode`, `jablotron_encode`). The emitted block is what you would write to a T5577 to clone a " +
		"Viking credential for an authorized test.\n\n" +
		"Builds the documented frame: the 24-bit 0xF20000 preamble, the 32-bit card ID, then the 8-bit checksum " +
		"set so the XOR of all eight bytes equals 0xA8. No confidently-wrong output: the layout + checksum are " +
		"the same Proxmark3-/Flipper-cross-verified ones `viking_decode` uses, and the encoder **round-trips** " +
		"with it (decoding the emitted block reproduces the card ID) and reproduces the reference vector (card " +
		"0x0001A337 → F200000001A337CF). Generation only — transmits nothing and writes to no device, so it is " +
		"Low risk.\n\n" +
		"Input: **card** (0 - 4294967295, the 32-bit Viking card ID).\n\n" +
		"Source: docs/catalog/gap-analysis.md (the inverse of viking_decode). Wrap-vs-native: native — fixed bit " +
		"placement + an XOR checksum, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"card":{"type":"integer","description":"The 32-bit Viking card ID (0 - 4294967295)."}
		},
		"required":["card"]
	}`),
	Required:  []string{"card"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vikingEncodeHandler,
}

func vikingEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	card, err := intField(p, "card", 0, 4294967295)
	if err != nil {
		return "", fmt.Errorf("viking_encode: %w", err)
	}
	block := viking.Encode(uint32(card))
	out := map[string]any{
		"format":    "Viking",
		"card_id":   card,
		"block_hex": block,
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
