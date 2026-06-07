// ioprox_encode.go — host-side IO Prox (Kantech XSF) LF block generator Spec,
// the inverse of ioprox_decode, delegating to internal/ioprox.Encode.
//
// Wrap-vs-native: native — fixed bit placement in a 64-bit block + an 8-bit
// additive checksum; stdlib only. Round-trips with ioprox_decode. The
// clone-block generator closing the ioProx reader-cloning loop, alongside
// em4100_encode / rfid_pacs_encode. Offline transform, transmits nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/ioprox"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ioproxEncodeSpec)
}

var ioproxEncodeSpec = Spec{
	Name: "ioprox_encode",
	Description: "Generate the 64-bit **IO Prox (Kantech XSF)** LF data block from a facility code, version and " +
		"16-bit card number — the inverse of `ioprox_decode`, closing the ioProx **reader-cloning loop** " +
		"alongside `em4100_encode` and `rfid_pacs_encode` (the block is what you would write to a T5577 to clone " +
		"a Kantech credential for an authorized test). \n\n" +
		"Builds the documented frame: nine zero preamble bits, the 0xF0 marker, the six framing separators, then " +
		"facility / version / card-high / card-low, and recomputes the 8-bit checksum (0xFF - (0xF0 + facility + " +
		"version + cardHi + cardLo)) so the emitted block always carries a correct CRC. No confidently-wrong " +
		"output: the layout + checksum are the same (Proxmark3- and Flipper-cross-verified) ones `ioprox_decode` " +
		"uses, and the encoder **round-trips** with it (decoding the emitted block reproduces the inputs) and " +
		"reproduces the hand-traced reference vector (FC=1 / V=1 / Card=1337 → 007840603059CF3F). Produces the " +
		"block only — it transmits nothing and writes to no device, so it is Low risk.\n\n" +
		"Inputs: **facility** (0-255), **version** (0-255), **card** (0-65535).\n\n" +
		"Source: docs/catalog/gap-analysis.md (the inverse of ioprox_decode; the ioProx clone-generation half of " +
		"the LF reader-cloning set). Wrap-vs-native: native — fixed bit placement + an 8-bit checksum, stdlib " +
		"only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"facility":{"type":"integer","description":"Facility code (0-255)."},
			"version":{"type":"integer","description":"Version byte (0-255)."},
			"card":{"type":"integer","description":"16-bit card number (0-65535)."}
		},
		"required":["facility","version","card"]
	}`),
	Required:  []string{"facility", "version", "card"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ioproxEncodeHandler,
}

func ioproxEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	fc, err := intField(p, "facility", 0, 255)
	if err != nil {
		return "", fmt.Errorf("ioprox_encode: %w", err)
	}
	ver, err := intField(p, "version", 0, 255)
	if err != nil {
		return "", fmt.Errorf("ioprox_encode: %w", err)
	}
	card, err := intField(p, "card", 0, 65535)
	if err != nil {
		return "", fmt.Errorf("ioprox_encode: %w", err)
	}
	block := ioprox.Encode(byte(fc), byte(ver), uint16(card))
	out := map[string]any{
		"format":        "IO Prox XSF (Kantech)",
		"facility_code": fc,
		"version":       ver,
		"card_number":   card,
		"block_hex":     block,
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}

// intField reads an integer parameter and bounds-checks it.
func intField(p map[string]any, name string, lo, hi int) (int, error) {
	v, ok := p[name]
	if !ok {
		return 0, fmt.Errorf("%q is required", name)
	}
	f, ok := v.(float64)
	if !ok {
		return 0, fmt.Errorf("%q must be a number", name)
	}
	n := int(f)
	if float64(n) != f {
		return 0, fmt.Errorf("%q must be a whole number", name)
	}
	if n < lo || n > hi {
		return 0, fmt.Errorf("%q must be in [%d, %d]", name, lo, hi)
	}
	return n, nil
}
