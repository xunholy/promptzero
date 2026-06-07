// cyfral_decode.go — host-side Cyfral iButton frame decoder Spec, delegating to
// internal/cyfral.
//
// Wrap-vs-native: native — a nibble walk + a 4-entry pattern map; stdlib only.
// The dedicated decoder for the Cyfral iButton format that internal/ibutton
// (Dallas 1-Wire) deferred (alongside Metakom). Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/cyfral"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(cyfralDecodeSpec)
}

var cyfralDecodeSpec = Spec{
	Name: "cyfral_decode",
	Description: "Decode a **Cyfral iButton frame** — the contact-key format used by Cyfral intercom systems " +
		"(common across the former-CIS / Eastern-European residential market). Cyfral is the second of the two " +
		"non-Dallas iButton formats `ibutton_decode` (Dallas 1-Wire) deferred (the first, Metakom, is " +
		"`metakom_decode`).\n\n" +
		"**Takes the on-wire frame, not the rendered 2-byte ID.** A Cyfral key decodes to a 16-bit value, but " +
		"that value carries **no integrity information** — every 16-bit value is a structurally valid decoded " +
		"key. The integrity lives in the on-wire encoding: a 40-bit frame of ten 4-bit nibbles — a start nibble " +
		"(0b0001), eight data nibbles each of which must be one of exactly four patterns " +
		"(1110/1101/1011/0111, carrying 2 bits each), and a stop nibble (0b0001). This validates those " +
		"constraints — a strong gate — and extracts the 16-bit key. Decoding the rendered 2-byte ID would be a " +
		"no-op with no verification, so that is deliberately not what this accepts.\n\n" +
		"No confidently-wrong output: the frame structure and the 2-bit nibble mapping (E→11 / D→10 / B→01 / " +
		"7→00) are taken from the Flipper Zero firmware (`protocol_cyfral.c`); the nibble constraints are a " +
		"strong structural gate (~(4/16)^8 false-accept), so a frame that fails any of them is **rejected** as " +
		"not-a-Cyfral-frame rather than mis-decoded; the mapping is hand-checkable, so no external vector is " +
		"needed. No network, no device, transmits nothing, so it is Low risk. The input is the 40-bit on-wire " +
		"frame as 10 hex nibbles (5 bytes), MSB-nibble first. ':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (the second non-Dallas iButton decoder deferred by " +
		"ibutton_decode). Wrap-vs-native: native — a nibble walk + a 4-entry pattern map, stdlib only, no new " +
		"go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The 40-bit on-wire Cyfral frame as 10 hex nibbles (5 bytes): start nibble + 8 data nibbles + stop nibble. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   cyfralDecodeHandler,
}

func cyfralDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("cyfral_decode: 'hex' is required")
	}
	res, err := cyfral.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("cyfral_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
