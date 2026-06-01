// ble_ibeacon_encode.go — host-side Apple iBeacon builder Spec, the
// inverse of the iBeacon decode in ble_continuity_classify, delegating to
// internal/applecontinuity.Encode.
//
// Wrap-vs-native: native — iBeacon is Apple's public, universally
// implemented manufacturer-data format (company ID 0x004C, type 0x02,
// length 0x15: 16-byte UUID + BE major + BE minor + signed measured power);
// pure byte assembly, no crypto, no hardware. Output is round-trip-verified
// against the Apple Continuity decoder.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/applecontinuity"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleIBeaconEncodeSpec)
}

var bleIBeaconEncodeSpec = Spec{
	Name: "ble_ibeacon_encode",
	Description: "Build an Apple iBeacon BLE manufacturer-data payload (Apple SIG 0x004C, message " +
		"type 0x02) from parameters — the offline inverse of the iBeacon decode in " +
		"ble_continuity_classify. Produces the exact bytes a beacon advertises, for proximity " +
		"red-team / beacon-spoofing / BLE-monitoring test workflows. Generation only — it advertises " +
		"nothing and touches no radio (pair with a BLE advertiser), so it is Low risk like the " +
		"decoder.\n\n" +
		"Fields: **uuid** (16-byte proximity UUID; dashed or plain hex), **major** + **minor** " +
		"(uint16 group/individual identifiers, big-endian on the wire), and **tx_power_dbm** (the " +
		"signed measured RSSI at 1 m, the value a phone uses for distance estimation).\n\n" +
		"`wrap` selects the framing: \"tlv\" (bare type/length/body, default), \"manufacturer\" " +
		"(0x4C 0x00 company-ID prefix), or \"ad\" (the full <len> FF 4C 00 … advertising-data record " +
		"ready for an advertising payload). Returns the bytes (hex) plus the message decoded back " +
		"from them for confirmation — round-trip-verified against the Apple Continuity decoder.\n\n" +
		"Scope: iBeacon only — the one Continuity message that is a clean, public, non-cryptographic " +
		"deterministic layout. Handoff / Nearby Info / AirDrop / Proximity Pairing carry encrypted " +
		"or device-derived bodies that cannot be synthesised offline, and Nearby Action is the " +
		"device-popup BLE-spam primitive this project does not generate by policy. Companion to " +
		"ble_continuity_classify / ble_continuity_decode. Wrap-vs-native: native — public layout, " +
		"pure byte assembly, no radio.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uuid":{"type":"string","description":"16-byte proximity UUID (dashed 8-4-4-4-12 or plain hex; separators and 0x tolerated)."},
			"major":{"type":"integer","description":"Major value (uint16, 0..65535)."},
			"minor":{"type":"integer","description":"Minor value (uint16, 0..65535)."},
			"tx_power_dbm":{"type":"integer","description":"Measured power: signed RSSI at 1 m (-128..127), used by receivers for distance estimation."},
			"wrap":{"type":"string","description":"Framing: tlv (bare, default), manufacturer (4C 00 prefix), or ad (full advertising-data record)."}
		},
		"required":["uuid"]
	}`),
	Required:  []string{"uuid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleIBeaconEncodeHandler,
}

func bleIBeaconEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	uuid := str(p, "uuid")
	if strings.TrimSpace(uuid) == "" {
		return "", fmt.Errorf("ble_ibeacon_encode: 'uuid' is required")
	}
	major, err := uint16Of(p["major"], "major")
	if err != nil {
		return "", fmt.Errorf("ble_ibeacon_encode: %w", err)
	}
	minor, err := uint16Of(p["minor"], "minor")
	if err != nil {
		return "", fmt.Errorf("ble_ibeacon_encode: %w", err)
	}
	tx := intOf(p["tx_power_dbm"])
	if tx < -128 || tx > 127 {
		return "", fmt.Errorf("ble_ibeacon_encode: tx_power_dbm %d out of int8 range (-128..127)", tx)
	}
	b, err := applecontinuity.Encode(applecontinuity.EncodeRequest{
		Kind: "ibeacon", UUID: uuid, Major: major, Minor: minor, TXPower: int8(tx), Wrap: str(p, "wrap"),
	})
	if err != nil {
		return "", fmt.Errorf("ble_ibeacon_encode: %w", err)
	}
	back, _ := applecontinuity.Decode(hex.EncodeToString(b))
	out, _ := json.MarshalIndent(struct {
		Hex     string                  `json:"hex"`
		Decoded *applecontinuity.Result `json:"decoded_back,omitempty"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}, "", "  ")
	return string(out), nil
}

// uint16Of coerces a JSON number to a uint16 with a range check.
func uint16Of(v any, field string) (uint16, error) {
	f, ok := v.(float64)
	if !ok {
		return 0, fmt.Errorf("%s is required (0..65535)", field)
	}
	if f < 0 || f > 65535 {
		return 0, fmt.Errorf("%s %v out of uint16 range (0..65535)", field, f)
	}
	return uint16(f), nil
}
