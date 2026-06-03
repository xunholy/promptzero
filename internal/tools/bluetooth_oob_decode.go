// bluetooth_oob_decode.go — host-side Bluetooth Out-Of-Band (OOB) pairing
// record dissector Spec, delegating to internal/btoob.
//
// Wrap-vs-native: native — the EIR/AD walk is the shared internal/ble
// DecodeGAPBytes walker; this adds only the BR/EDR framing header (length
// + BD_ADDR) and routes both OOB variants through it. The framing and the
// LE Role / device-address value formats are taken from the Bluetooth Core
// Specification Supplement Part A and the NFC Forum "Bluetooth Secure
// Simple Pairing Using NFC" application document (as in the ndeflib
// reference). Offline read of operator-supplied bytes — no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/btoob"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bluetoothOOBDecodeSpec)
}

var bluetoothOOBDecodeSpec = Spec{
	Name: "bluetooth_oob_decode",
	Description: "Decode a Bluetooth Out-Of-Band (OOB) pairing record — the **tap-to-pair** payload carried " +
		"by an NFC handover tag and the Bluetooth Secure Simple Pairing OOB data block. Recovers the peer's " +
		"Bluetooth address, device class / LE role, local name, and the SSP OOB key material a tag offers for " +
		"an authenticated tap-to-pair exchange.\n\n" +
		"Fields: **hex** (the OOB record, hex — ':' / '-' / '_' / whitespace ignored) and **variant** " +
		"(`br_edr` for `application/vnd.bluetooth.ep.oob`, the default; `le` for " +
		"`application/vnd.bluetooth.le.oob`).\n\n" +
		"- **BR/EDR** (Easy Pairing): a 2-byte little-endian OOB Data Length + a 6-byte little-endian " +
		"Bluetooth Device Address (BD_ADDR), then optional EIR attributes. The declared length is checked " +
		"against the actual size (mismatch noted, not asserted).\n" +
		"- **LE**: a bare sequence of AD structures including the LE Bluetooth Device Address (0x1B, 6 " +
		"address bytes + a public/random type flag) and LE Role (0x1C → Peripheral / Central / preferred).\n\n" +
		"Both variants run through the shared BLE EIR/AD walker, so Class of Device (Major Device Class " +
		"named), Flags, service-UUID lists, local name, appearance, and manufacturer data are decoded; the " +
		"SSP OOB key material (Hash C / Randomizer R, LE SC confirmation/random, Security Manager TK) is " +
		"surfaced as raw hex — opaque key bytes, not guessed at. No confidently-wrong output.\n\n" +
		"Pure offline decode of operator-supplied bytes — no hardware, transmits nothing, so it is Low " +
		"risk. The same record is decoded automatically when it appears as the MIME payload of an " +
		"`ndef_decode` record. Wrap-vs-native: native — thin BR/EDR framing over the shared EIR walker.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Bluetooth OOB record. ':' / '-' / '_' / whitespace separators tolerated."},
			"variant":{"type":"string","enum":["br_edr","le"],"description":"OOB framing: 'br_edr' (application/vnd.bluetooth.ep.oob, default) or 'le' (application/vnd.bluetooth.le.oob)."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bluetoothOOBDecodeHandler,
}

func bluetoothOOBDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("bluetooth_oob_decode: 'hex' is required")
	}
	res, err := btoob.DecodeHex(str(p, "variant"), raw)
	if err != nil {
		return "", fmt.Errorf("bluetooth_oob_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
