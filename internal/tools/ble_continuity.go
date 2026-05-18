// ble_continuity.go — host-side Apple Continuity dissector Spec
// delegating to the internal/ble package for the walker proper.
//
// Wrap-vs-native judgement: Apple Continuity is a reverse-engineered
// public spec — furiousMAC/continuity, hexway's AppleJuice, and the
// AppleBleee writeups document the TLV layout. The dissector is a
// short walker over a byte slice. Wrapping a FAP for this would
// require an SD-card install + a firmware-fork dependency for a
// pure parser. Native delivers offline analysis (paste a btmon /
// Wireshark hex blob and decode without a Flipper attached),
// unit-testable round-trips, and a per-type field catalog the
// operator can extend without rebuilding firmware.
//
// Pairs with the defensive Apple-Continuity-spam detector in
// internal/defense — that one decides whether an advertisement
// matches the Flipper-spam signature; this one decodes the
// advertisement into named action types so an operator can audit
// what's actually on the air at a venue.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ble"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleContinuityDecodeSpec)
}

var bleContinuityDecodeSpec = Spec{
	Name: "ble_continuity_decode",
	Description: "Decode an Apple Continuity BLE manufacturer-data payload (Apple SIG 0x004C) into " +
		"a structured list of action TLVs with named types — Nearby Info, Nearby Action, Handoff, " +
		"Proximity Pairing (AirPods/Beats), AirDrop, Magic Switch, Instant Hotspot Tethering, " +
		"iBeacon, plus the named-only types in furiousMAC's catalog. For documented types the " +
		"public-facing fields (status flags, battery nibbles, device-model IDs, action codes) are " +
		"surfaced by name; unknown or out-of-catalog types still appear with their type byte and " +
		"raw value hex so the operator can flag novel signatures. Pure offline parser — no Flipper " +
		"required; useful for decoding a btmon / Wireshark / NRF Connect capture without bringing " +
		"hardware into the loop. Accepts ':' '-' '_' / whitespace separators, plus the optional " +
		"0x4C00 manufacturer-ID prefix or full <len> FF 4C 00 ... AD-structure wrapper.\n\n" +
		"Pairs with defense_classify_advertisement — that one flags Flipper-spam signatures; this " +
		"one decodes legitimate traffic.\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 rank 8 (ble_continuity_classify). Wrap-vs-native: " +
		"native — the format is a public reverse-engineered spec, the walker is ~150 lines, no " +
		"hardware needed.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Apple Continuity payload. Accepts bare TLVs, optional 4C00 manufacturer prefix, or full <len> FF 4C 00 ... AD-structure prefix. ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleContinuityDecodeHandler,
}

func bleContinuityDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ble_continuity_decode: 'hex' is required")
	}
	cont, err := ble.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ble_continuity_decode: %w", err)
	}
	out, _ := json.MarshalIndent(cont, "", "  ")
	return string(out), nil
}
