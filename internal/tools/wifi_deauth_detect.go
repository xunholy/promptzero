// wifi_deauth_detect.go — host-side defensive 802.11 deauth/disassoc-flood
// detector Spec, delegating to internal/wifidefense.AnalyzeDeauth.
//
// Wrap-vs-native: native — detecting a deauth flood from a capture is a
// deterministic transform over management-frame metadata (subtype +
// destination + BSSID + reason code), no SDR/adapter at analysis time.
// Defensive sibling of tpms_anomaly_detect and subghz_rollback_detect.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wifidefense"
)

func init() { //nolint:gochecknoinits
	Register(wifiDeauthDetectSpec)
}

var wifiDeauthDetectSpec = Spec{
	Name: "wifi_deauth_detect",
	Description: "Defensive blue-team analysis of a SEQUENCE of decoded 802.11 frames for the " +
		"signatures of a deauthentication / disassociation flood — the canonical WiFi denial-of-" +
		"service (aireplay-0 / MDK4 / the Marauder + ESP32 deauth attack). Feed the already-decoded " +
		"frame fields (e.g. from wifi_80211) in observation order; the analyser does no RF work.\n\n" +
		"Three signals, each an OBSERVATION with its benign explanation stated — never a verdict:\n" +
		" - **broadcast_deauth** (warning): deauth/disassoc frames addressed to the broadcast address " +
		"kick every client in the BSS at once. There is no benign reason to broadcast-deauth, so this " +
		"is the clearest flood signature; the only innocent explanation is a misbehaving AP/driver.\n" +
		" - **deauth_flood** (warning): the deauth+disassoc count exceeds `flood_threshold` (default " +
		"10). Consistent with an aireplay/MDK4/Marauder flood OR a very unstable RF environment / an " +
		"AP shedding load — correlate with the reason-code mix.\n" +
		" - **targeted_client** (info): one destination takes a disproportionate share of the deauths " +
		"from one BSSID — a targeted disconnect (e.g. to force a WPA-handshake recapture) rather than " +
		"an indiscriminate flood.\n\n" +
		"Also surfaces the deauth/disassoc/broadcast counts and a named 802.11 reason-code histogram. " +
		"Non-management subtypes count toward the total only. Pure offline analyser — no WiFi adapter. " +
		"Companion to wifi_80211 / wifi_rsn_decode / wifi_wps_decode. Wrap-vs-native: native — a pure " +
		"sequence transform over frame metadata, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"frames":{
				"type":"array",
				"description":"Decoded 802.11 frames in observation order.",
				"items":{
					"type":"object",
					"properties":{
						"subtype":{"type":"string","description":"Frame subtype — 'deauth' / 'disassoc' drive the analysis; others count toward the total only."},
						"src":{"type":"string","description":"Transmitter MAC (separators tolerated)."},
						"dst":{"type":"string","description":"Destination MAC; FF:FF:FF:FF:FF:FF is the broadcast (mass-deauth) address."},
						"bssid":{"type":"string","description":"BSS identifier MAC."},
						"reason":{"type":"integer","description":"802.11 reason code (e.g. 7 = class-3 frame from nonassociated STA)."}
					},
					"required":["subtype"]
				}
			},
			"flood_threshold":{"type":"integer","description":"deauth+disassoc count above which deauth_flood fires (default 10)."}
		},
		"required":["frames"]
	}`),
	Required:  []string{"frames"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiDeauthDetectHandler,
}

func wifiDeauthDetectHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawFrames, ok := p["frames"].([]any)
	if !ok || len(rawFrames) == 0 {
		return "", fmt.Errorf("wifi_deauth_detect: 'frames' must be a non-empty array of objects")
	}
	frames := make([]wifidefense.Frame, 0, len(rawFrames))
	for i, rf := range rawFrames {
		m, ok := rf.(map[string]any)
		if !ok {
			return "", fmt.Errorf("wifi_deauth_detect: frames[%d] is not an object", i)
		}
		frames = append(frames, wifidefense.Frame{
			Subtype: str(m, "subtype"),
			Src:     str(m, "src"),
			Dst:     str(m, "dst"),
			BSSID:   str(m, "bssid"),
			Reason:  intOf(m["reason"]),
		})
	}
	threshold := intOf(p["flood_threshold"])

	res, err := wifidefense.AnalyzeDeauth(frames, threshold)
	if err != nil {
		return "", fmt.Errorf("wifi_deauth_detect: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
