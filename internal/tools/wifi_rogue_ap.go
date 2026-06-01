// wifi_rogue_ap.go — host-side defensive rogue-AP / evil-twin detector
// Spec, delegating to internal/wifidefense.AnalyzeRogueAP.
//
// Wrap-vs-native: native — detecting an evil twin from a beacon set is a
// deterministic transform over (SSID, BSSID, security-posture) tuples, no
// SDR/adapter at analysis time. Defensive sibling of wifi_deauth_detect;
// composes with wifi_rsn_decode (the posture) and wifi_80211.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wifidefense"
)

func init() { //nolint:gochecknoinits
	Register(wifiRogueAPDetectSpec)
}

var wifiRogueAPDetectSpec = Spec{
	Name: "wifi_rogue_ap_detect",
	Description: "Defensive blue-team analysis of a set of decoded 802.11 beacon / probe-response " +
		"observations for rogue-AP / evil-twin signatures. Feed the already-decoded (SSID, BSSID, " +
		"security-posture) tuples — e.g. SSID from wifi_80211 and the posture string from " +
		"wifi_rsn_decode (or \"Open\" when there's no RSN IE); the analyser does no RF work.\n\n" +
		"Three signals, each an OBSERVATION with its benign explanation stated — never a verdict:\n" +
		" - **security_mismatch** (warning): one SSID advertised with more than one distinct security " +
		"posture (e.g. Open AND WPA2). The classic evil-twin / downgrade lure — a rogue AP cloning a " +
		"protected network's name with weaker security to harvest associations. Benign: a site " +
		"mid-migration running mixed APs.\n" +
		" - **bssid_changed_security** (warning): a single BSSID's posture changes across the capture " +
		"— consistent with a spoofed/cloned BSSID or an AP hijack. Benign: a genuine reconfiguration.\n" +
		" - **ssid_multiple_bssid** (info): one SSID served by several BSSIDs with a consistent posture " +
		"— normal for enterprise roaming / mesh, surfaced so you can confirm every BSSID is yours.\n\n" +
		"Hidden SSIDs (empty name) are excluded from the SSID-grouped signals; output order is " +
		"deterministic (keys sorted). Pure offline analyser — no WiFi adapter. Companion to " +
		"wifi_rsn_decode / wifi_deauth_detect / wifi_80211. Wrap-vs-native: native — a pure transform " +
		"over (SSID, BSSID, posture) tuples, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"aps":{
				"type":"array",
				"description":"Decoded beacon/probe-response observations.",
				"items":{
					"type":"object",
					"properties":{
						"ssid":{"type":"string","description":"Network name (empty = hidden; excluded from SSID-grouped signals)."},
						"bssid":{"type":"string","description":"AP MAC / BSSID (separators tolerated)."},
						"security":{"type":"string","description":"Security posture, e.g. 'Open' or a wifi_rsn_decode string like 'WPA2-Personal (PSK)'."},
						"channel":{"type":"integer","description":"Optional channel number."}
					},
					"required":["ssid","bssid"]
				}
			}
		},
		"required":["aps"]
	}`),
	Required:  []string{"aps"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiRogueAPDetectHandler,
}

func wifiRogueAPDetectHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawAPs, ok := p["aps"].([]any)
	if !ok || len(rawAPs) == 0 {
		return "", fmt.Errorf("wifi_rogue_ap_detect: 'aps' must be a non-empty array of objects")
	}
	aps := make([]wifidefense.AP, 0, len(rawAPs))
	for i, ra := range rawAPs {
		m, ok := ra.(map[string]any)
		if !ok {
			return "", fmt.Errorf("wifi_rogue_ap_detect: aps[%d] is not an object", i)
		}
		aps = append(aps, wifidefense.AP{
			SSID:     str(m, "ssid"),
			BSSID:    str(m, "bssid"),
			Security: str(m, "security"),
			Channel:  intOf(m["channel"]),
		})
	}

	res, err := wifidefense.AnalyzeRogueAP(aps)
	if err != nil {
		return "", fmt.Errorf("wifi_rogue_ap_detect: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
