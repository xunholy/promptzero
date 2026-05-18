// ble_gap.go — host-side BLE GAP / EIR advertisement walker
// Spec, delegating to the internal/ble package for the parser
// proper.
//
// Wrap-vs-native judgement: the GAP advertisement format is a
// public Bluetooth SIG spec (Core Spec Vol 3 Part C §11 + the
// Assigned Numbers GAP document). The walker is a length-
// prefixed record loop with a small per-AD-type dispatcher.
// Wrapping a FAP for this would add an SD-card install step + a
// firmware-fork dependency for a pure parser. Native delivers
// offline analysis — operators paste a btmon / NRF Connect /
// Wireshark capture and decode the full advertisement before
// dispatching specific records (Continuity, Eddystone) to their
// dedicated decoders.
//
// Pairs with ble_continuity_decode (Apple manufacturer data
// 0x004C) and ble_eddystone_decode (service data 0xFEAA) —
// this walker is the generic outer-structure parser; those two
// decode specific inner payloads.

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
	Register(bleGAPDecodeSpec)
}

var bleGAPDecodeSpec = Spec{
	Name: "ble_gap_decode",
	Description: "Walk a raw BLE GAP / EIR advertisement payload — the generic outer structure " +
		"that every BLE advertisement uses. Decodes the (length, AD type, data) record loop and " +
		"surfaces per-record fields for the most common AD types:\n\n" +
		"- **Flags** (0x01): LE Limited / General Discoverable, BR/EDR Not Supported, etc.\n" +
		"- **Service UUID lists** (0x02-0x07): 16-bit / 32-bit / 128-bit Service UUIDs in their " +
		"Incomplete / Complete forms, decoded from wire-order little-endian to canonical " +
		"big-endian rendering.\n" +
		"- **Local Name** (0x08 Shortened / 0x09 Complete): UTF-8 device name.\n" +
		"- **TX Power Level** (0x0A): signed int8 dBm.\n" +
		"- **Service Data 16-bit UUID** (0x16): UUID + opaque service-specific payload + " +
		"well-known-service name lookup (e.g. Eddystone 0xFEAA, Exposure Notification 0xFD6F).\n" +
		"- **Appearance** (0x19): 2-byte device-category code with coarse-category name lookup " +
		"(Heart Rate Sensor, Earbud, etc.).\n" +
		"- **Manufacturer Specific Data** (0xFF): 2-byte SIG company ID + opaque vendor payload " +
		"+ company-name lookup (Apple 0x004C, Microsoft 0x0006, Google 0x00E0, etc.).\n\n" +
		"Operators dispatch the inner payload of recognised records to dedicated decoders — " +
		"ble_continuity_decode for Apple manufacturer data (company 0x004C), ble_eddystone_decode " +
		"for Eddystone service data (UUID 0xFEAA).\n\n" +
		"Tolerates ':' / '-' / '_' / whitespace separators. Handles the zero-length terminator " +
		"used to pad fixed-size BLE buffers (31 bytes for legacy adv, 255 bytes for extended).\n\n" +
		"Source: docs/catalog/gap-analysis.md (BLE decode space). Wrap-vs-native: native — the " +
		"GAP advertisement format is a fully public Bluetooth SIG spec, the walker is a record " +
		"loop with per-type field decoders.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded BLE GAP / EIR advertisement payload. ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleGAPDecodeHandler,
}

func bleGAPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ble_gap_decode: 'hex' is required")
	}
	res, err := ble.DecodeGAP(raw)
	if err != nil {
		return "", fmt.Errorf("ble_gap_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
