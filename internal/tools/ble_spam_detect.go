// ble_spam_detect.go — host-side defensive BLE-spam flood detector Spec,
// delegating to internal/defense.AnalyzeSpamBatch.
//
// Wrap-vs-native: native — the per-advertisement spam classifier already
// exists (defense_classify_advertisement / internal/defense.Classify) but
// is stateless; the cross-advertisement flood signal (many rotating MACs
// emitting one spam family) is only reachable via the internal Tracker,
// which no tool exposes. This batch analyser surfaces that signal — the BLE
// analogue of wifi_deauth_detect.

package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/xunholy/promptzero/internal/defense"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bleSpamDetectSpec)
}

var bleSpamDetectSpec = Spec{
	Name: "ble_spam_detect",
	Description: "Defensive blue-team analysis of a SEQUENCE of captured BLE advertisements for an " +
		"active BLE-spam flood — the Flipper / ESP32 advertisement-spam attack (AppleJuice / SourApple " +
		"Apple-Continuity device-popups, Microsoft Swift Pair, Google Fast Pair). " +
		"defense_classify_advertisement flags a single malformed advert; this adds the signal it " +
		"cannot see across one packet: how many DISTINCT source MACs are emitting each spam " +
		"signature.\n\n" +
		"Spam tools rotate the advertiser address per packet, so a genuine flood shows as many " +
		"distinct MACs all carrying the same malformed family — that is the characteristic signature, " +
		"and it is flagged when the distinct-MAC count for a signature reaches `flood_threshold` " +
		"(default 8). A single buggy beacon re-randomising its address, or a genuinely busy venue, is " +
		"the benign explanation, so this is framed as an OBSERVATION, not a verdict.\n\n" +
		"Per-signature it reports the total matches, the distinct-source-MAC count, and the flood " +
		"flag; repeats from one MAC count as a single source (so a chatty beacon does not look like a " +
		"flood). Each advertisement is the same shape defense_classify_advertisement accepts. Pure " +
		"offline analyser — no BLE radio. Companion to defense_classify_advertisement / " +
		"ble_continuity_classify. Wrap-vs-native: native — reuses the in-repo signature classifier; a " +
		"pure batch transform, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"advertisements":{
				"type":"array",
				"description":"Captured BLE advertisements, each shaped like defense_classify_advertisement's input.",
				"items":{
					"type":"object",
					"properties":{
						"address":{"type":"string","description":"Source MAC AA:BB:CC:DD:EE:FF (the rotating address; distinct MACs per signature drive the flood signal)."},
						"local_name":{"type":"string","description":"GAP local name (optional)."},
						"service_uuids":{"type":"array","items":{"type":"string"},"description":"Advertised service UUIDs (optional)."},
						"manufacturer_data":{"type":"object","description":"Map of manufacturer ID (decimal int as string) to hex payload, e.g. {\"76\":\"000501020304 05\"} for Apple."},
						"manufacturer_data_b64":{"type":"object","description":"Same as manufacturer_data but base64 values."},
						"service_data":{"type":"object","description":"Map of service UUID (decimal int as string) to hex payload."}
					}
				}
			},
			"flood_threshold":{"type":"integer","description":"Distinct source-MAC count per signature above which a flood is flagged (default 8)."}
		},
		"required":["advertisements"]
	}`),
	Required:  []string{"advertisements"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bleSpamDetectHandler,
}

func bleSpamDetectHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	rawAds, ok := p["advertisements"].([]any)
	if !ok || len(rawAds) == 0 {
		return "", fmt.Errorf("ble_spam_detect: 'advertisements' must be a non-empty array of objects")
	}
	ads := make([]defense.Advertisement, 0, len(rawAds))
	for i, ra := range rawAds {
		m, ok := ra.(map[string]any)
		if !ok {
			return "", fmt.Errorf("ble_spam_detect: advertisements[%d] is not an object", i)
		}
		ad, err := parseAdvertisement(m)
		if err != nil {
			return "", fmt.Errorf("ble_spam_detect: advertisements[%d]: %w", i, err)
		}
		ads = append(ads, ad)
	}
	threshold := intOf(p["flood_threshold"])

	res := defense.AnalyzeSpamBatch(ads, threshold)
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
