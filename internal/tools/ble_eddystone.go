// ble_eddystone.go — host-side Google Eddystone BLE-beacon
// dissector Spec, delegating to the internal/ble package for the
// frame-type walker proper.
//
// Wrap-vs-native judgement: Eddystone is a fully open public spec
// (google/eddystone). The decoder is a one-byte frame-type switch
// over a service-data payload with documented UID / URL / TLM /
// EID layouts. Wrapping a FAP for this would require an SD-card
// install + a firmware-fork dependency for a pure parser. Native
// delivers offline analysis (paste a btmon / Wireshark hex blob
// and decode without a Flipper attached), inline test coverage
// against the worked examples in the spec, and complements the
// existing ble_continuity_decode (Apple manufacturer-data space)
// with the Google service-data space.

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
	Register(bleEddystoneDecodeSpec)
}

var bleEddystoneDecodeSpec = Spec{
	Name: "ble_eddystone_decode",
	Description: "Decode a Google Eddystone BLE-beacon service-data payload (service UUID 0xFEAA) " +
		"into the structured frame type — UID (16-byte namespace+instance ID), URL (encoded URL " +
		"with scheme byte + TLD-compression table), TLM (telemetry: battery mV, temperature, advert " +
		"count, uptime), or EID (rotating ephemeral ID). Reserved bytes in URL frames are " +
		"surfaced in a reserved_bytes list rather than silently dropped; eTLM (encrypted " +
		"telemetry, version 0x01) is recognised by name but not dissected.\n\n" +
		"Auto-strips the optional 0xAAFE service-UUID prefix or the full " +
		"<len> 16 AA FE ... AD-structure wrapper, so operators can paste hex from any common tool " +
		"without preprocessing. Tolerates ':' / '-' / '_' / whitespace separators.\n\n" +
		"Pure offline parser — no Flipper required. Complements ble_continuity_decode (Apple " +
		"manufacturer-data space) by covering the Google service-data space.\n\n" +
		"Source: docs/catalog/gap-analysis.md §3 (BLE beacon decode space adjacent to rank 8). " +
		"Wrap-vs-native: native — Eddystone is a fully open spec at " +
		"github.com/google/eddystone, the walker is a one-byte switch over four frame layouts.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Eddystone service-data payload. Accepts bare frame, optional 0xAAFE UUID prefix, or full <len> 16 AA FE ... AD-structure prefix. ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleEddystoneDecodeHandler,
}

func bleEddystoneDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ble_eddystone_decode: 'hex' is required")
	}
	res, err := ble.DecodeEddystone(raw)
	if err != nil {
		return "", fmt.Errorf("ble_eddystone_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
