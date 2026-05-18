// bluetooth_gatt.go — host-side Bluetooth GATT UUID enumerator
// Spec, delegating to the internal/btuuid package for the
// lookup proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/btuuid"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bluetoothGATTUUIDLookupSpec)
}

var bluetoothGATTUUIDLookupSpec = Spec{
	Name: "bluetooth_gatt_uuid_lookup",
	Description: "Resolve a Bluetooth SIG-assigned GATT UUID to its canonical name + category " +
		"(Service / Characteristic / Descriptor). Accepts both 16-bit short form (e.g. '180F' " +
		"for Battery) and 128-bit canonical form (with or without hyphens — operators paste " +
		"either form from their bluetoothctl / nRF Connect / btmon / Flipper BT scan output).\n\n" +
		"Catalog covers:\n" +
		"- **~75 Services**: Generic Access (0x1800), Generic Attribute (0x1801), Device " +
		"Information (0x180A), Heart Rate (0x180D), Battery (0x180F), Human Interface Device " +
		"(0x1812), Environmental Sensing (0x181A), full BLE Audio stack (0x1843-0x1859), Mesh " +
		"(0x1827/0x1828), plus proprietary 0xFEXX services (Eddystone, Google Fast Pair, " +
		"COVID-19 Exposure Notification, Apple AirTag, Tile, Apple iBeacon).\n" +
		"- **~120 Characteristics**: Device Name (0x2A00), Battery Level (0x2A19), Heart Rate " +
		"Measurement (0x2A37), Temperature (0x2A6E), Humidity (0x2A6F), Manufacturer Name " +
		"(0x2A29), HID Report (0x2A4D), and the full Environmental Sensing + Health + Fitness " +
		"characteristic set.\n" +
		"- **~16 Descriptors**: CCCD (0x2902 — the most common, for subscribing to " +
		"notifications), Characteristic User Description (0x2901), Server Characteristic " +
		"Configuration (0x2903), Characteristic Presentation Format (0x2904), Valid Range " +
		"(0x2906), Report Reference (0x2908), Environmental Sensing Configuration (0x290B).\n\n" +
		"128-bit UUIDs that match the SIG base pattern " +
		"(0000XXXX-0000-1000-8000-00805F9B34FB) get the short form extracted automatically. " +
		"Vendor-allocated random 128-bit UUIDs (e.g. Nordic UART Service, manufacturer-specific " +
		"app services) are flagged as 'vendor_specific' with no name lookup.\n\n" +
		"Pure offline parser — no Flipper / BLE adapter required. Pairs with the existing BLE " +
		"decoders (ble_gap_decode for advertisement records, ble_continuity_decode / " +
		"ble_eddystone_decode for specific service payloads, bluetooth_cod_decode for the BT " +
		"Classic side). Accepts '0x' prefix and ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (BLE decode space). Wrap-vs-native: native — " +
		"Bluetooth Assigned Numbers (GATT Services / Characteristics / Descriptors documents) " +
		"are fully public, the walker is a lookup + 128-bit base-pattern detector.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"uuid":{"type":"string","description":"GATT UUID to resolve. 16-bit short form ('180F') or 128-bit canonical ('0000180F-0000-1000-8000-00805F9B34FB' or unhyphenated). Accepts '0x' prefix and ':' / '-' / '_' / whitespace separators."}
		},
		"required":["uuid"]
	}`),
	Required:  []string{"uuid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bluetoothGATTUUIDLookupHandler,
}

func bluetoothGATTUUIDLookupHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "uuid")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("bluetooth_gatt_uuid_lookup: 'uuid' is required")
	}
	res, err := btuuid.Lookup(raw)
	if err != nil {
		return "", fmt.Errorf("bluetooth_gatt_uuid_lookup: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
