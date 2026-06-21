// cyfral_encode.go — host-side Cyfral iButton on-wire frame generator Spec, the
// inverse of cyfral_decode, delegating to internal/cyfral.Encode.
//
// Wrap-vs-native: native — fixed nibble placement (start/stop 0b0001 + eight
// 2-bit data nibbles) in a 40-bit frame; stdlib only. Round-trips with
// cyfral_decode for every 16-bit key. The Cyfral clone-prep generator, the
// non-Dallas iButton companion to ibutton_encode. Offline transform, transmits
// nothing.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/cyfral"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(cyfralEncodeSpec)
}

var cyfralEncodeSpec = Spec{
	Name: "cyfral_encode",
	Description: "Generate the 40-bit on-wire **Cyfral iButton** frame from a 16-bit key — the inverse of " +
		"`cyfral_decode`, the Cyfral clone-prep generator (the non-Dallas iButton companion to `ibutton_encode`). " +
		"Cyfral contact keys are used by intercom systems across the former-CIS / Eastern-European residential " +
		"market; this builds the frame you would emulate or write to a blank to clone a key for an authorized " +
		"test.\n\n" +
		"A Cyfral key's integrity lives entirely in the on-wire frame (the rendered 2-byte ID carries none), so " +
		"this emits that frame: a 0b0001 start nibble, eight data nibbles each encoding two bits of the key " +
		"(most-significant pair first, mapping 11->E / 10->D / 01->B / 00->7), and a 0b0001 stop nibble — 10 " +
		"nibbles / 5 bytes, MSB-nibble first. **No confidently-wrong output**: the frame structure and the 2-bit " +
		"nibble mapping are the same ones `cyfral_decode` uses (taken from the Flipper Zero firmware " +
		"protocol_cyfral.c), and the encoder **round-trips** with it for every 16-bit key (decoding the emitted " +
		"frame reproduces the key) — verified exhaustively over all 65536 keys, no external vector needed. The " +
		"on-air bit-period timing is the writer's concern and out of scope, exactly as on the decode side. " +
		"Produces the frame only — it transmits nothing and writes to no device, so it is Low risk.\n\n" +
		"Input: **key** (0-65535, the 16-bit Cyfral key). Wrap-vs-native: native — fixed nibble placement, " +
		"stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"key":{"type":"integer","description":"The 16-bit Cyfral key (0-65535)."}
		},
		"required":["key"]
	}`),
	Required:  []string{"key"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   cyfralEncodeHandler,
}

func cyfralEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	key, err := intField(p, "key", 0, 65535)
	if err != nil {
		return "", fmt.Errorf("cyfral_encode: %w", err)
	}
	frame := cyfral.EncodeHex(uint16(key))
	out := map[string]any{
		"format":        "Cyfral iButton",
		"key":           key,
		"key_hex":       fmt.Sprintf("%04X", key),
		"on_wire_frame": frame,
		"note":          "40-bit on-wire frame (start 0b0001 + 8 data nibbles + stop 0b0001); on-air bit-period timing is the writer's concern. Generation only — transmits nothing.",
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	return string(b), nil
}
