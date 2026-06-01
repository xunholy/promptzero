// wifi_wps.go — host-side WPS / Wi-Fi Simple Configuration data-element
// dissector Spec, delegating to the internal/wps package.
//
// Wrap-vs-native: native — the WSC attribute format is a public,
// deterministic TLV (2-byte BE type + 2-byte BE length + value) documented
// in the Wi-Fi Simple Configuration spec and implemented identically by
// hostapd / wpa_supplicant / reaver / bully / wash. The existing
// wifi_80211 vendor-IE decoder identifies the WPS IE but leaves its body
// opaque; this turns that body into the WPS recon fields.

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
	Register(wifiWPSDecodeSpec)
}

var wifiWPSDecodeSpec = Spec{
	Name: "wifi_wps_decode",
	Description: "Decode the WPS (Wi-Fi Simple Configuration) data elements carried in the WPS " +
		"vendor-specific Information Element of an 802.11 beacon or probe response — the same fields " +
		"`wash` / `reaver` read to triage WPS attack surface. The wifi_80211 decoder identifies the " +
		"WPS IE (Microsoft OUI 00:50:F2, vendor type 0x04) but leaves its body as opaque hex; this " +
		"walks that body's WSC attribute TLVs (2-byte type + 2-byte length + value).\n\n" +
		"Lifts the recon-relevant fields to the top level:\n" +
		" - **version** and **setup_state** (Configured / Not Configured).\n" +
		" - **ap_setup_locked** — the decisive one: reaver/bully PIN brute force is useless against a " +
		"locked AP.\n" +
		" - **device_password_id** (Default PIN vs PushButton vs …) and the **Config Methods** bitmask " +
		"(Label / Display / Keypad / Push Button / NFC …) — whether a PIN attack even applies.\n" +
		" - device identity strings (Device Name, Manufacturer, Model) and UUID-E.\n\n" +
		"Accepts the bare WSC attribute stream, the manufacturer payload prefixed with the OUI+type " +
		"(00 50 F2 04 …), or the full vendor IE (DD <len> 00 50 F2 04 …); the recognised prefix is " +
		"stripped. Only spec-documented attribute IDs / enums are named — an unknown attribute or " +
		"value is surfaced with its raw hex and numeric type, never guessed; a truncated TLV stops " +
		"the walk with a note. ':' / '-' / '_' / whitespace separators tolerated.\n\n" +
		"Pure offline parser — no WiFi adapter required. Companion to wifi_80211 / wifi_eapol_decode. " +
		"Wrap-vs-native: native — public WSC TLV format, a short walker, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded WPS IE body. Accepts the bare WSC attribute stream, the 00 50 F2 04 ... manufacturer payload, or the full DD <len> 00 50 F2 04 ... vendor IE. Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiWPSDecodeHandler,
}

func wifiWPSDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("wifi_wps_decode: 'hex' is required")
	}
	res, err := wps.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("wifi_wps_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
