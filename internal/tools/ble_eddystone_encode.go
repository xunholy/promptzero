// ble_eddystone_encode.go — host-side Google Eddystone BLE-beacon builder
// Spec, the inverse of ble_eddystone_decode, delegating to
// internal/ble.EncodeEddystone.
//
// Wrap-vs-native: native — Eddystone is a fully open public spec
// (github.com/google/eddystone); encoding is pure byte assembly + the URL
// scheme/expansion lookup the decoder already documents. Output is
// round-trip-verified against ble_eddystone_decode and the byte-exact
// examples in the Eddystone-URL spec.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ble"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleEddystoneEncodeSpec)
}

var bleEddystoneEncodeSpec = Spec{
	Name: "ble_eddystone_encode",
	Description: "Build a Google Eddystone BLE-beacon service-data payload (service UUID 0xFEAA) from " +
		"parameters — the offline inverse of ble_eddystone_decode. Produces the exact bytes a beacon " +
		"advertises, for beacon spoofing / proximity-marketing red-team / BLE-monitoring test " +
		"workflows. Generation only — it advertises nothing and touches no radio (pair with a BLE " +
		"advertiser), so it is Low risk like the decoder.\n\n" +
		"Supported frame types (`kind`):\n" +
		" - **url** — URL frame; the longest-matching scheme prefix (http://www., https://www., " +
		"http://, https://) and the TLD expansions (.com/.org/.net/… with and without a trailing " +
		"slash) are abbreviated to their 1-byte Eddystone codes automatically; other printable-ASCII " +
		"bytes pass through.\n" +
		" - **uid** — 16-byte beacon ID: `namespace` (10-byte hex) + `instance` (6-byte hex).\n" +
		" - **tlm** — unencrypted telemetry (version 0x00): `battery_mv`, `temperature_c` (encoded as " +
		"8.8 fixed point), `adv_count`, `uptime_100ms`.\n" +
		" - **eid** — frames a caller-supplied 8-byte `ephemeral_id` (the rotating token is owned " +
		"out-of-band; this does not derive it).\n\n" +
		"`tx_power_dbm` (uid/url/eid) is the calibrated TX power at 0 m, signed (-128..127). `wrap` " +
		"selects the framing: \"frame\" (bare, default), \"uuid\" (0xAA 0xFE prefix), or \"ad\" (the " +
		"full <len> 16 AA FE … Service-Data AD structure ready for an advertising payload).\n\n" +
		"Returns the bytes (hex) plus the frame decoded back from them for confirmation — round-trip-" +
		"verified against ble_eddystone_decode. Deferred: eTLM (encrypted telemetry) and EID " +
		"derivation (need the per-beacon identity key + AES). Companion to ble_eddystone_decode. " +
		"Wrap-vs-native: native — open spec, pure byte assembly, no radio.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"kind":{"type":"string","description":"Frame type: uid, url, tlm, or eid."},
			"tx_power_dbm":{"type":"integer","description":"For uid/url/eid: calibrated TX power at 0 m, signed (-128..127)."},
			"url":{"type":"string","description":"For kind=url: the full URL (e.g. https://www.example.com)."},
			"namespace":{"type":"string","description":"For kind=uid: 10-byte namespace as hex."},
			"instance":{"type":"string","description":"For kind=uid: 6-byte instance as hex."},
			"battery_mv":{"type":"integer","description":"For kind=tlm: battery voltage in mV (0..65535)."},
			"temperature_c":{"type":"number","description":"For kind=tlm: temperature in °C (8.8 fixed point, -128..127.996)."},
			"adv_count":{"type":"integer","description":"For kind=tlm: advertising PDU count since boot (uint32)."},
			"uptime_100ms":{"type":"integer","description":"For kind=tlm: time since boot in 0.1 s units (uint32)."},
			"ephemeral_id":{"type":"string","description":"For kind=eid: 8-byte ephemeral ID as hex."},
			"wrap":{"type":"string","description":"Framing: frame (bare, default), uuid (AA FE prefix), or ad (full Service-Data AD structure)."}
		},
		"required":["kind"]
	}`),
	Required:  []string{"kind"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleEddystoneEncodeHandler,
}

func bleEddystoneEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	kind := str(p, "kind")
	if strings.TrimSpace(kind) == "" {
		return "", fmt.Errorf("ble_eddystone_encode: 'kind' is required (uid, url, tlm, eid)")
	}
	req := ble.EddystoneEncodeRequest{
		Kind:         kind,
		TxPower:      intOf(p["tx_power_dbm"]),
		URL:          str(p, "url"),
		Namespace:    str(p, "namespace"),
		Instance:     str(p, "instance"),
		BatteryMV:    intOf(p["battery_mv"]),
		TemperatureC: floatOf(p["temperature_c"]),
		AdvCount:     intOf(p["adv_count"]),
		Uptime100ms:  intOf(p["uptime_100ms"]),
		EphemeralID:  str(p, "ephemeral_id"),
		Wrap:         str(p, "wrap"),
	}
	b, err := ble.EncodeEddystone(req)
	if err != nil {
		return "", fmt.Errorf("ble_eddystone_encode: %w", err)
	}
	back, _ := ble.DecodeEddystone(hex.EncodeToString(b))
	out, _ := json.MarshalIndent(struct {
		Hex     string        `json:"hex"`
		Decoded ble.Eddystone `json:"decoded_back"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}, "", "  ")
	return string(out), nil
}

// intOf coerces a JSON number (float64) to an int, tolerating nil/non-number as 0.
func intOf(v any) int {
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return 0
}

// floatOf coerces a JSON number to a float64, tolerating nil/non-number as 0.
func floatOf(v any) float64 {
	if f, ok := v.(float64); ok {
		return f
	}
	return 0
}
