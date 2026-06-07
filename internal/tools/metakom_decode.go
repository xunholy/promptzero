// metakom_decode.go — host-side Metakom iButton key decoder Spec, delegating to
// internal/metakom.
//
// Wrap-vs-native: native — a 4-byte read + a per-byte even-parity popcount;
// stdlib only. The dedicated decoder for the Metakom iButton width that
// internal/ibutton (Dallas 1-Wire) explicitly deferred. Offline read, no
// hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/metakom"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(metakomDecodeSpec)
}

var metakomDecodeSpec = Spec{
	Name: "metakom_decode",
	Description: "Decode a **Metakom iButton key** — the 4-byte (32-bit) contact-key format used by Metakom " +
		"intercom systems (common across the former-CIS / Eastern-European residential market). Metakom is one " +
		"of the two non-Dallas iButton formats the project's `ibutton_decode` (Dallas 1-Wire) explicitly " +
		"deferred (the other is Cyfral); this is the dedicated decoder for the Metakom width.\n\n" +
		"Input is the *decoded* 4-byte key — the bytes a Flipper Zero iButton read emits (the 'ID: AB CD EF 12' " +
		"value), MSB-first. The on-wire framing (the sync bit, the 0b010 start/stop words, the bit-period " +
		"timing) is the reader's concern and out of scope; this decodes the 4-byte key.\n\n" +
		"No confidently-wrong output: the key width, the byte order and the validity rule — every data byte must " +
		"have an **even** number of 1 bits — are taken from the Flipper Zero firmware " +
		"(`protocol_metakom.c` `metakom_parity_check`), and the rule is hand-checkable by counting bits (no " +
		"external vector needed). Metakom carries no stronger structural marker, so the per-byte even parity is " +
		"the only integrity gate (a comparatively weak ~1-in-16 gate) — a key that fails it is reported as " +
		"**parity-invalid** rather than asserted as genuine, and the raw bytes are always surfaced. No network, " +
		"no device, transmits nothing, so it is Low risk. The input is the 4-byte Metakom key. ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (the non-Dallas iButton decoder deferred by ibutton_decode). " +
		"Wrap-vs-native: native — a 4-byte read + a per-byte even-parity popcount, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The 4-byte Metakom key (the Flipper 'ID' value) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   metakomDecodeHandler,
}

func metakomDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("metakom_decode: 'hex' is required")
	}
	res, err := metakom.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("metakom_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
