// bleadv_decode.go — host-side Bluetooth advertising / scan-response (GAP AD
// structure / BR-EDR EIR) decoder Spec, delegating to internal/bleadv.
//
// Wrap-vs-native: native — an advertising payload is a flat list of
// [length][AD type][data] structures, each with a documented fixed layout
// (LE UUIDs, the Flags bitfield, signed TX power, a 2-byte company id, the
// iBeacon / Eddystone sub-formats); a length-prefixed TLV walk + small tables,
// stdlib only. The advertising-layer recon decoder of the BT stack — what a
// passive BLE scan surfaces first. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bleadv"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleAdvDecodeSpec)
}

var bleAdvDecodeSpec = Spec{
	Name: "bt_adv_decode",
	Description: "Decode a **Bluetooth advertising / scan-response payload** — the GAP **AD-structure** list " +
		"(Bluetooth Core spec Vol 3 Part C §11 + the Assigned Numbers / Core Specification Supplement). The same " +
		"length-type-value format is the BR/EDR **Extended Inquiry Response (EIR)**, so this decodes EIR too.\n\n" +
		"A BLE advertising payload is what every **passive BLE scan surfaces first** — the Flipper Zero 'BLE " +
		"scan', an ESP32 Marauder / nRF sniffer, a phone's nRF Connect: before any connection or GATT traffic " +
		"(`bt_hci_decode` → `bt_l2cap_decode` → `bt_att_decode`), the advertising data is the **recon headline**. " +
		"It carries the device's advertised **name**, its discoverability / **role flags**, the **service UUIDs** " +
		"it offers, its **TX power** and **appearance**, and — most usefully for fingerprinting — " +
		"**manufacturer-specific data**: **Apple iBeacon** (proximity UUID + major/minor + measured power), " +
		"**Eddystone** beacons (UID / URL / TLM telemetry), and the **company identifier** of the chipset / " +
		"vendor behind an otherwise anonymous device. It is the advertising-layer complement to the project's " +
		"Bluetooth-stack decode chain.\n\n" +
		"Decodes each AD structure: Flags (the discoverability / BR-EDR-not-supported bits), the 16/32/128-bit " +
		"service-UUID and solicitation lists, Shortened / Complete Local Name, Tx Power Level, Appearance, LE " +
		"Role, URI, Service Data (with the Eddystone UID/URL/TLM frame decode for UUID 0xFEAA), and Manufacturer " +
		"Specific Data (company name + the iBeacon sub-format).\n\n" +
		"No confidently-wrong output: the AD type numbers, the Flags bits, the service-UUID layouts, the company " +
		"identifier assignment and the iBeacon / Eddystone sub-formats follow the Bluetooth Assigned Numbers and " +
		"the published iBeacon / Eddystone specs. Where a value space is open-ended or undocumented (an unknown " +
		"AD type, an unknown company id, a manufacturer blob other than iBeacon such as Apple's proprietary " +
		"Continuity stream, service data for a UUID other than Eddystone's 0xFEAA), the bytes are surfaced **raw** " +
		"with a note rather than guessed. No network, no device, transmits nothing, so it is Low risk. The input " +
		"is the advertising / scan-response / EIR payload (the AD-structure bytes). ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (BLE-scan recon; advertising-layer complement to bt_hci_decode → " +
		"bt_l2cap_decode → bt_att_decode). Wrap-vs-native: native — a length-prefixed TLV walk + small lookup " +
		"tables, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The Bluetooth advertising / scan-response payload (or BR/EDR EIR) — the GAP AD-structure bytes — as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleAdvDecodeHandler,
}

func bleAdvDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("bt_adv_decode: 'hex' is required")
	}
	res, err := bleadv.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("bt_adv_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
