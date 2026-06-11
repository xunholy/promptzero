// bluez_pairing_decode.go — host-side Bluetooth pairing-key extractor Spec,
// delegating to internal/bluezkeys.
//
// Wrap-vs-native: native — a minimal GKeyFile (INI) scanner over the documented
// BlueZ storage format; no new go.mod dep. The BLE/Bluetooth analogue of
// wifi_config_decode: a foothold on a Linux host yields the long-term pairing
// keys for every bonded device. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bluezkeys"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bluezPairingDecodeSpec)
}

var bluezPairingDecodeSpec = Spec{
	Name: "bluez_pairing_decode",
	Description: "Extract **Bluetooth pairing keys** from a Linux **BlueZ device `info` file** " +
		"(`/var/lib/bluetooth/<adapter>/<device>/info`) — the BLE/Bluetooth analogue of `wifi_config_decode`. " +
		"A foothold on a Linux host yields, for every device it has bonded with, the long-term cryptographic " +
		"material: the **BR/EDR LinkKey**, and for LE the **LongTermKey (LTK)**, **IdentityResolvingKey " +
		"(IRK)**, and signing keys (CSRK). With these an operator can **decrypt sniffed traffic** for the " +
		"bonded link, **resolve a device's resolvable-private address** (IRK), or **impersonate** the bonded " +
		"device — directly useful alongside a BLE sniffer or the Flipper's BLE radio.\n\n" +
		"Reports the device name, transport (BR/EDR / LE / dual), address type, and each recovered key with " +
		"its parameters (LTK EncSize/EDiv/Rand, LinkKey type). The keys are the **explicit extraction goal**, " +
		"so they are surfaced **verbatim** (the device MAC is the info file's directory name — supplied by " +
		"path, not in the file). **No confidently-wrong output**: the file is recognised only by a " +
		"BlueZ-specific key section; an unpaired / cleared file (no key sections) is **rejected**, not " +
		"guessed; and input that is not a BlueZ info file is rejected. No network, no device, transmits " +
		"nothing — Low risk. Pairs with the SMP / BLE tooling.\n\n" +
		"Source: docs/catalog/gap-analysis.md (BLE / credential forensics). Wrap-vs-native: native — a " +
		"GKeyFile (INI) scanner over the documented BlueZ storage format (doc/settings-storage.txt; " +
		"src/device.c), no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"info":{"type":"string","description":"The BlueZ device 'info' file contents."}
		},
		"required":["info"]
	}`),
	Required:  []string{"info"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bluezPairingDecodeHandler,
}

func bluezPairingDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	info := strings.TrimSpace(str(p, "info"))
	if info == "" {
		return "", fmt.Errorf("bluez_pairing_decode: 'info' is required")
	}
	res, err := bluezkeys.Decode(info)
	if err != nil {
		return "", fmt.Errorf("bluez_pairing_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
