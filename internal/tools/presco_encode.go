// presco_encode.go — host-side Presco LF block generator Spec, the inverse of
// presco_decode, delegating to internal/presco.Encode.
//
// Wrap-vs-native: native — place the 32-bit full code after the fixed 0x10D00000
// preamble + two zero words; stdlib only. Round-trips with presco_decode. The
// final clone-block generator completing the LF set (em4100/pacs/ioprox/
// jablotron/viking/noralsy encoders). Offline transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/presco"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(prescoEncodeSpec)
}

var prescoEncodeSpec = Spec{
	Name: "presco_encode",
	Description: "Generate the 128-bit **Presco** LF data block from a 32-bit full code — the inverse of " +
		"`presco_decode`, completing the LF clone-generation set (`em4100_encode`, `rfid_pacs_encode`, " +
		"`ioprox_encode`, `jablotron_encode`, `viking_encode`, `noralsy_encode`). Presco readers are used for " +
		"gate / garage / building access; the emitted block is what you would write to a T5577 to clone a Presco " +
		"credential for an authorized test.\n\n" +
		"Builds the documented frame: the 0x10D00000 preamble, two zero words, then the 32-bit full code (from " +
		"which site code = (full>>24)&0xFF and user code = full&0xFFFF derive). Presco carries no checksum, so " +
		"the structural frame is the integrity gate. No confidently-wrong output: the layout is the same one " +
		"`presco_decode` uses (from the Proxmark3 `cmdlfpresco.c` encoder/decoder, which are inverse), and this " +
		"encoder **round-trips** with the decoder (decoding the emitted block reproduces the full code) and " +
		"reproduces the reference vector (full code 0x07AABBCC → 10D00000000000000000000007AABBCC). Generation " +
		"only — transmits nothing and writes to no device, so it is Low risk.\n\n" +
		"Input: **full_code** (0 - 4294967295, the 32-bit Presco full code).\n\n" +
		"Source: docs/catalog/gap-analysis.md (the inverse of presco_decode; completes the LF clone-generation " +
		"set). Wrap-vs-native: native — fixed-frame placement, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"full_code":{"type":"integer","description":"The 32-bit Presco full code (0 - 4294967295)."}
		},
		"required":["full_code"]
	}`),
	Required:  []string{"full_code"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   prescoEncodeHandler,
}

func prescoEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	full, err := intField(p, "full_code", 0, 4294967295)
	if err != nil {
		return "", fmt.Errorf("presco_encode: %w", err)
	}
	block := presco.Encode(uint32(full))
	out := map[string]any{
		"format":    "Presco",
		"full_code": full,
		"site_code": (full >> 24) & 0xFF,
		"user_code": full & 0xFFFF,
		"block_hex": block,
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
