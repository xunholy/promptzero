// wifi_config_decode.go — host-side stored-WiFi-credential extractor Spec,
// delegating to internal/wificonfig.
//
// Wrap-vs-native: native — hand scanners for the wpa_supplicant block syntax and
// the NetworkManager INI + stdlib encoding/xml for the Windows WLAN profile; no
// new go.mod dep. The host-side complement to the RF-side WiFi tooling: a
// foothold's saved configs hand over the PSKs directly, no handshake/crack
// needed. Offline; no network or device.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wificonfig"
)

func init() { //nolint:gochecknoinits
	Register(wifiConfigDecodeSpec)
}

var wifiConfigDecodeSpec = Spec{
	Name: "wifi_config_decode",
	Description: "Extract **stored WiFi network credentials** from a host config file — the host-side " +
		"complement to the project's RF-side WiFi tooling. Once an operator has a foothold on a host, its " +
		"saved WiFi configs hand over the **pre-shared keys directly** — no handshake capture or cracking " +
		"required. Recognises the five standard formats: **wpa_supplicant.conf** (Linux / embedded / " +
		"routers), **NetworkManager `.nmconnection`** keyfiles (Linux desktop), the **Windows `netsh wlan " +
		"export profile` XML**, the **Android `WifiConfigStore.xml`** (`/data/misc/wifi/`), and the **OpenWrt " +
		"`/etc/config/wireless`** UCI file. For each network it reports the **SSID**, the security type " +
		"(WPA-PSK / WPA-EAP / WEP / OPEN), the recovered **PSK** (passphrase or 64-hex PMK), and for " +
		"enterprise networks the EAP method + **identity** + password.\n\n" +
		"The recovered key is the **explicit extraction goal**, so — unlike the credential-*container* " +
		"decoders that only flag a secret's presence — the passphrase **is** surfaced (it is the loot). **No " +
		"confidently-wrong output**: the format is detected by its unambiguous syntax; a Windows key stored " +
		"**DPAPI-`protected`** is reported as **encrypted** (the plaintext is not invented); an open network " +
		"is reported key-less; and input matching none of the three formats is rejected. No network, no " +
		"device, transmits nothing — Low risk. Pairs with the WiFi attack tooling (`wifi_wps_decode`, the " +
		"Marauder handshake workflow).\n\n" +
		"Source: docs/catalog/gap-analysis.md (WiFi / credential forensics). Wrap-vs-native: native — hand " +
		"scanners + stdlib encoding/xml, no new go.mod dep; formats per wpa_supplicant.conf(5), NetworkManager " +
		"nm-settings keyfile, and the Microsoft WLAN_profile schema.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"config":{"type":"string","description":"The WiFi config file contents (wpa_supplicant.conf / .nmconnection / netsh WLAN profile XML)."}
		},
		"required":["config"]
	}`),
	Required:  []string{"config"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiConfigDecodeHandler,
}

func wifiConfigDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	cfg := strings.TrimSpace(str(p, "config"))
	if cfg == "" {
		return "", fmt.Errorf("wifi_config_decode: 'config' is required")
	}
	res, err := wificonfig.Decode(cfg)
	if err != nil {
		return "", fmt.Errorf("wifi_config_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
