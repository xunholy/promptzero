// applecontinuity.go — host-side Apple Continuity BLE
// advertisement decoder Spec. Wraps the internal/applecontinuity
// walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/applecontinuity"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleContinuityClassifySpec)
}

var bleContinuityClassifySpec = Spec{
	Name: "ble_continuity_classify",
	Description: "Decode an Apple Continuity BLE advertisement payload — the " +
		"Manufacturer-Specific-Data blob Apple devices broadcast for Handoff, AirDrop, " +
		"Nearby Info / Action, AirPods proximity pairing, iBeacon, Hey Siri, and the " +
		"other ad-hoc connectivity primitives that make the Apple ecosystem feel " +
		"'magical' on a sniffer. Pure offline parser sourced from furiousMAC (Mertens " +
		"et al. 2019), AppleJuice, hexway/apple_bleee, the Wireshark BTBR/BLE " +
		"dissectors, and TU Darmstadt's continuity protocol research. Decodes:\n\n" +
		"- **Outer envelope tolerance** — accepts (a) the full advertising-data " +
		"record (length + 0xFF Manufacturer Specific Data type + 0x4C00 Apple Company " +
		"ID + TLVs); (b) just the post-AdvType manufacturer data (0x4C00 + TLVs); " +
		"(c) the raw TLV stream by itself. Auto-detects and reports which envelope " +
		"was found.\n" +
		"- **TLV walker** — each message inside the stream is " +
		"(Type[1] + Length[1] + Value[Length]). Multiple messages per advertisement " +
		"are common (Nearby Info + Handoff frequently appear together).\n" +
		"- **Type table** (15 documented types):\n" +
		"  - 0x02 iBeacon / 0x03 AirPrint / 0x04 AirDrop / 0x05 HomeKit / 0x06 " +
		"Proximity Pairing (AirPods / Beats) / 0x07 Hey Siri / 0x08 AirPlay Source / " +
		"0x09 AirPlay Target / 0x0A Magic Switch (Apple Pencil) / 0x0B Watch " +
		"Connection / 0x0C Handoff / 0x0D Wi-Fi Settings Target / 0x0E Tethering " +
		"Target (Instant Hotspot) / 0x0F Nearby Action / 0x10 Nearby Info.\n" +
		"- **Per-type body decoding** (headline fields surfaced):\n" +
		"  - **iBeacon** (0x02, length 21): UUID (16-byte standard formatted) + Major " +
		"(uint16 BE) + Minor (uint16 BE) + TX Power (int8 dBm).\n" +
		"  - **Handoff** (0x0C, variable): Clipboard-state byte + IV (2 bytes) + " +
		"AuthTag (1 byte) + Encrypted Payload.\n" +
		"  - **Nearby Info** (0x10, variable): StatusFlags high-nibble (decoded as " +
		"PrimaryiCloud / AirDrop / AutoUnlockActive / AutoUnlockEnabled) + ActionCode " +
		"low-nibble (15-entry name table covering iOS lock / home / FaceTime / driving " +
		"/ etc.) + DataFlags + AuthTag.\n" +
		"  - **Nearby Action** (0x0F, variable): ActionFlags + ActionType (15-entry " +
		"table covering Wi-Fi Password / Apple TV Setup / Apple Pay / Watch Setup / " +
		"Companion Link / etc.) + AuthTag + optional ActionParameters.\n" +
		"  - **AirDrop** (0x04, length 9): Status byte + 8-byte identifier hash.\n" +
		"  - **Hey Siri** (0x07, length 5): 5 hash bytes used to wake Siri across " +
		"devices.\n" +
		"  - **Proximity Pairing** (0x06, variable): Device model (2-byte BE — " +
		"e.g. 0x0220 AirPods Pro) + status flags + battery levels (left pod / " +
		"right pod / case in 10% steps) + lid state.\n" +
		"- **Other types** — surfaced with Type + TypeName + Length + raw hex body. " +
		"Operators who need full dissection of AirPlay / HomeKit / Watch frames can " +
		"read the bytes directly.\n" +
		"- **Multi-TLV summary** — per-advertisement opcode-sequence summary string " +
		"(e.g. 'Nearby Info + Handoff') for triage.\n\n" +
		"Pure offline parser — operators paste the Manufacturer Specific Data bytes " +
		"from a Wireshark BLE capture, a Sniffle / CatSniffer dump, an `hcidump` " +
		"trace, an `nRF Connect` advertisement export, or any BLE scanner and inspect " +
		"every documented field. Defensive primitive — used to identify Apple devices " +
		"in the area without participating in their pairing flows.\n\n" +
		"Out of scope (deferred): the BLE Link-Layer / Advertising PDU framing (handled " +
		"by `ble_classify` / `ble_findmy_*`); AppleID / phone / email / OfflineFinding " +
		"key reversal (encrypted material surfaced as hex; decryption belongs in a " +
		"separate Spec); Handoff payload decryption (IV + AuthTag surfaced but " +
		"cipher-text is opaque without the pairing key); the BLE GAP / GATT layer " +
		"beyond the advertising data record.\n\n" +
		"Source: docs/catalog/gap-analysis.md top-30 #8 (BLE Continuity classifier; " +
		"pairs with the audit's `workflow_apple_continuity_audit`). Wrap-vs-native: " +
		"native — protocol is fully reverse-engineered by furiousMAC / AppleJuice / " +
		"Wireshark dissectors; wire format is a tight TLV walker, no crypto at this " +
		"layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Apple Continuity advertisement bytes as hex. Accepts the full AD record (length + 0xFF + 0x4C00 + TLVs), the post-AdvType manufacturer data (0x4C00 + TLVs), or the raw TLV stream. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleContinuityClassifyHandler,
}

func bleContinuityClassifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ble_continuity_classify: 'hex' is required")
	}
	res, err := applecontinuity.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ble_continuity_classify: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
