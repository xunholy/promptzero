// ble_altbeacon.go — host-side AltBeacon BLE-beacon codec Specs (decode +
// encode), delegating to internal/altbeacon. AltBeacon is the open,
// vendor-neutral beacon standard, the counterpart to Apple iBeacon
// (ble_continuity_classify / ble_ibeacon_encode) and Google Eddystone
// (ble_eddystone_decode / ble_eddystone_encode).
//
// Wrap-vs-native: native — AltBeacon is a fully open spec
// (github.com/AltBeacon/spec); a manufacturer-specific-data structure of a
// company ID + the 0xBEAC beacon code + 20-byte beacon ID + reference RSSI
// + reserved byte. Pure byte assembly, no crypto, no radio. Verified by
// round-trip and the canonical spec worked example.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/altbeacon"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleAltBeaconDecodeSpec)
	Register(bleAltBeaconEncodeSpec)
}

var bleAltBeaconDecodeSpec = Spec{
	Name: "ble_altbeacon_decode",
	Description: "Decode an AltBeacon BLE advertisement — the open, vendor-neutral beacon standard " +
		"(github.com/AltBeacon/spec), the counterpart to Apple iBeacon and Google Eddystone. Parses " +
		"the manufacturer-specific-data structure: 2-byte company ID + the 0xBEAC beacon code + " +
		"20-byte beacon ID + 1-byte reference RSSI + 1-byte manufacturer-reserved value.\n\n" +
		"Auto-strips three input framings: the full advertising-data record (<len> FF <mfgid> BE AC " +
		"…), the bare manufacturer-specific-data payload (<mfgid> BE AC …), or a payload already " +
		"starting at the 0xBEAC beacon code. The 20-byte beacon ID is surfaced opaquely AND, as a " +
		"convenience, split into the common 16-byte UUID + 2-byte major + 2-byte minor interpretation " +
		"(the spec itself treats the ID as opaque). ':' / '-' / '_' / whitespace separators and a 0x " +
		"prefix tolerated.\n\n" +
		"Pure offline parser — no Flipper required. Companion to ble_altbeacon_encode. " +
		"Wrap-vs-native: native — open spec, a short walker over a fixed byte layout, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded AltBeacon advertisement. Accepts the full <len> FF <mfgid> BE AC ... AD record, the bare <mfgid> BE AC ... manufacturer data, or a payload starting at BE AC. Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleAltBeaconDecodeHandler,
}

func bleAltBeaconDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ble_altbeacon_decode: 'hex' is required")
	}
	res, err := altbeacon.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ble_altbeacon_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}

var bleAltBeaconEncodeSpec = Spec{
	Name: "ble_altbeacon_encode",
	Description: "Build an AltBeacon BLE advertisement (the open beacon standard) from parameters — " +
		"the offline inverse of ble_altbeacon_decode. Produces the manufacturer-specific-data bytes a " +
		"beacon advertises, for proximity red-team / beacon-spoofing / BLE-monitoring test workflows. " +
		"Generation only — it advertises nothing and touches no radio, so it is Low risk like the " +
		"decoder.\n\n" +
		"Fields: **beacon_id** (20-byte opaque ID as hex; commonly a 16-byte UUID + 2-byte major + " +
		"2-byte minor concatenated), **mfg_id** (advertiser company ID, default 0x0118 Radius " +
		"Networks), **ref_rssi_dbm** (signed reference RSSI at 1 m), and **mfg_reserved** (the " +
		"manufacturer-reserved byte, 0..255). `wrap` selects \"manufacturer\" (bare <mfgid> BE AC …, " +
		"default) or \"ad\" (the full <len> FF … advertising-data record).\n\n" +
		"Returns the bytes (hex) plus the advertisement decoded back for confirmation — round-trip-" +
		"verified against ble_altbeacon_decode and the canonical AltBeacon spec example. Companion to " +
		"ble_altbeacon_decode. Wrap-vs-native: native — open spec, pure byte assembly, no radio.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"beacon_id":{"type":"string","description":"20-byte beacon ID as hex (e.g. a 16-byte UUID + 2-byte major + 2-byte minor). Separators / 0x tolerated."},
			"mfg_id":{"type":"integer","description":"Advertiser company ID (uint16, 0..65535). Default 0x0118 (Radius Networks)."},
			"ref_rssi_dbm":{"type":"integer","description":"Reference RSSI at 1 m, signed (-128..127)."},
			"mfg_reserved":{"type":"integer","description":"Manufacturer-reserved byte (0..255, default 0)."},
			"wrap":{"type":"string","description":"Framing: manufacturer (bare, default) or ad (full advertising-data record)."}
		},
		"required":["beacon_id"]
	}`),
	Required:  []string{"beacon_id"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleAltBeaconEncodeHandler,
}

func bleAltBeaconEncodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	beaconID := str(p, "beacon_id")
	if strings.TrimSpace(beaconID) == "" {
		return "", fmt.Errorf("ble_altbeacon_encode: 'beacon_id' is required")
	}
	req := altbeacon.EncodeRequest{
		BeaconID:    beaconID,
		MfgReserved: intOf(p["mfg_reserved"]),
		Wrap:        str(p, "wrap"),
	}
	if v, ok := p["mfg_id"].(float64); ok {
		if v < 0 || v > 65535 {
			return "", fmt.Errorf("ble_altbeacon_encode: mfg_id %v out of uint16 range (0..65535)", v)
		}
		req.MfgID = uint16(v)
	}
	tx := intOf(p["ref_rssi_dbm"])
	if tx < -128 || tx > 127 {
		return "", fmt.Errorf("ble_altbeacon_encode: ref_rssi_dbm %d out of int8 range (-128..127)", tx)
	}
	req.RefRSSI = int8(tx)

	b, err := altbeacon.Encode(req)
	if err != nil {
		return "", fmt.Errorf("ble_altbeacon_encode: %w", err)
	}
	back, _ := altbeacon.Decode(hex.EncodeToString(b))
	out, _ := json.MarshalIndent(struct {
		Hex     string               `json:"hex"`
		Decoded *altbeacon.AltBeacon `json:"decoded_back,omitempty"`
	}{Hex: strings.ToUpper(hex.EncodeToString(b)), Decoded: back}, "", "  ")
	return string(out), nil
}
