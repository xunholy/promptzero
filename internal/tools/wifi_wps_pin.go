// wifi_wps_pin.go — host-side WPS PIN checksum validator / completer Spec,
// delegating to the internal/wps package.
//
// Wrap-vs-native: native — the WPS PIN checksum is a tiny public,
// deterministic algorithm (the reaver / bully wps_pin_checksum). Pairs with
// wifi_wps_decode: decode the WPS IE, and if WPS is unlocked with the PIN
// method, validate captured PINs or generate the 8th (check) digit for a
// brute-force prefix.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wps"
)

func init() { //nolint:gochecknoinits
	Register(wifiWPSPINSpec)
}

var wifiWPSPINSpec = Spec{
	Name: "wifi_wps_pin",
	Description: "Validate or complete a WPS PIN using the Wi-Fi Simple Configuration PIN-checksum " +
		"algorithm (the same routine reaver / bully use). The 8-digit device PIN is a 7-digit prefix " +
		"plus a check digit computed from it, so the 8th digit is not free entropy — a brute force " +
		"only searches the 10^7 prefixes.\n\n" +
		" - Give an **8-digit** PIN → it reports whether the check digit is valid (and the expected " +
		"digit if not). An invalid checksum means the PIN can never be the device PIN.\n" +
		" - Give a **7-digit** prefix → it returns the check digit and the full 8-digit PIN — the " +
		"prefix→PIN step in a WPS PIN brute force.\n\n" +
		"Universally-cited weak defaults (12345670, 00000000) are flagged. Vendor-specific default-PIN " +
		"derivations (ComputePIN from the BSSID — the large reaver/bully per-device PIN databases) are " +
		"deliberately NOT embedded: they are device-specific and a partial table would be " +
		"confidently-wrong. Pairs with wifi_wps_decode (which tells you whether WPS is enabled, " +
		"unlocked, and PIN-capable). Separators are tolerated. Pure offline math — no radio. " +
		"Wrap-vs-native: native — a few lines of public checksum arithmetic, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pin":{"type":"string","description":"A 7-digit prefix (to complete with its check digit) or an 8-digit PIN (to validate). Digits only; separators tolerated."}
		},
		"required":["pin"]
	}`),
	Required:  []string{"pin"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiWPSPINHandler,
}

func wifiWPSPINHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	pin := str(p, "pin")
	if strings.TrimSpace(pin) == "" {
		return "", fmt.Errorf("wifi_wps_pin: 'pin' is required (7-digit prefix or 8-digit PIN)")
	}
	res, err := wps.CheckPIN(pin)
	if err != nil {
		return "", fmt.Errorf("wifi_wps_pin: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
