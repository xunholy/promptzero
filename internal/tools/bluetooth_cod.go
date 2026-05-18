// bluetooth_cod.go — host-side Bluetooth Class of Device (CoD)
// dissector Spec, delegating to the internal/btclassic package
// for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/btclassic"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bluetoothCoDDecodeSpec)
}

var bluetoothCoDDecodeSpec = Spec{
	Name: "bluetooth_cod_decode",
	Description: "Decode a 24-bit Bluetooth Class of Device (CoD) value — the device-type " +
		"identifier every Bluetooth Classic device advertises during inquiry. Per Bluetooth " +
		"Assigned Numbers Baseband §1.2. Decodes:\n\n" +
		"- **Major Device Class** (bits 12..8): Computer / Phone / LAN / Audio-Video / " +
		"Peripheral / Imaging / Wearable / Toy / Health / Uncategorized / Miscellaneous.\n" +
		"- **Minor Device Class** (bits 7..2): sub-category specific to the major class. " +
		"Computer → Desktop / Laptop / Server / Tablet etc. Phone → Cellular / Cordless / " +
		"Smart / Wired Modem. Audio-Video → Headset / Hands-free / Microphone / Loudspeaker / " +
		"Headphones / Portable / Car Audio / etc. Peripheral → keyboard / pointing combo + " +
		"device type (joystick / gamepad / remote / tablet / etc.). Imaging → display / " +
		"camera / scanner / printer flag combination. Wearable → Wristwatch / Pager / Jacket / " +
		"Helmet / Glasses. Toy → Robot / Vehicle / Doll / Controller / Game. Health → Blood " +
		"Pressure / Thermometer / Scale / Glucose / Pulse Oximeter / Heart Rate / etc.\n" +
		"- **Service Classes** (bits 23..13): bitmap of advertised capabilities — Limited " +
		"Discoverable, LE Audio, Positioning, Networking, Rendering, Capturing, Object " +
		"Transfer, Audio, Telephony, Information.\n" +
		"- **Format Type** (bits 1..0): always 0 in the current spec; surfaced for callers " +
		"to flag non-standard values.\n\n" +
		"Pure offline parser — operators paste a CoD value from any BT inquiry tool " +
		"(hciconfig / bluetoothctl / btmon / nRF Connect / Marauder BT scan) and identify the " +
		"device class without a re-scan. Pairs with ble_continuity_decode / ble_eddystone_decode " +
		"/ ble_gap_decode (the BLE side); this is the BT Classic counterpart.\n\n" +
		"Accepts '0x' prefix and ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Bluetooth decode space). Wrap-vs-native: " +
		"native — Bluetooth Assigned Numbers Baseband §1.2 is fully public, the walker is a " +
		"24-bit bit-shift + per-major minor-class lookup tables.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"24-bit CoD hex (6 chars; e.g. '5A020C' for a Smart Phone with Telephony service). Accepts '0x' prefix and ':' / '-' / '_' / whitespace separators."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bluetoothCoDDecodeHandler,
}

func bluetoothCoDDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("bluetooth_cod_decode: 'hex' is required")
	}
	res, err := btclassic.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("bluetooth_cod_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
