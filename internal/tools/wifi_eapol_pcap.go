// wifi_eapol_pcap.go — host-side native WPA/WPA2 4-way-handshake-from-pcap
// extractor Spec, delegating to internal/eapolcap.
//
// Wrap-vs-native: native — composes the in-tree pcap / pcapng readers, the
// DS-bit-correct 802.11 frame parser, the EAPOL-Key dissector, and the
// mode-22000 line builder; no external binary. Removes the hcxpcapngtool
// shell-out for the dominant M1+M2 handshake case on a libpcap or pcapng
// capture, completing the type-02 half that wifi_pmkid_pcap (type-01) left to
// hcxpcapngtool. Offline; no network or device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/eapolcap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(wifiEAPOLPcapSpec)
}

var wifiEAPOLPcapSpec = Spec{
	Name: "wifi_eapol_pcap",
	Description: "Extract **WPA/WPA2 4-way-handshake** hashes from an **802.11 packet capture** and emit " +
		"ready-to-crack hashcat mode-22000 lines (type 02) — **natively, no hcxpcapngtool**. The 4-way " +
		"handshake is the classic WPA2 capture: when a client associates, message 1 (AP -> STA) carries the " +
		"ANonce and message 2 (STA -> AP) carries the MIC computed over the EAPOL frame, so the ANonce (from " +
		"M1), the MIC and the MIC-bearing frame (from M2), both MACs and the ESSID together form a crackable " +
		"hash. This walks the capture, pairs each M1 with its M2 (same BSSID, station MAC and 8-byte replay " +
		"counter — the structural guarantee they belong to the same exchange), resolves the ESSID from a " +
		"beacon / probe-response, and builds the `WPA*02*…` line for each. It is the client-handshake " +
		"counterpart of `wifi_pmkid_pcap` (the clientless-PMKID extractor) and completes the native pipeline " +
		"`wifi_eapol_hc22000` started.\n\n" +
		"It composes the in-tree decoders: the pcap reader, the **DS-bit-correct** 802.11 frame parser (so " +
		"the AP BSSID and station MAC are right for both the FromDS M1 and the ToDS M2), the EAPOL-Key " +
		"dissector, and the mode-22000 line builder (anchored on hashcat's published example). Both " +
		"**classic libpcap** and **pcapng** (the format Marauder / hcxdumptool write) are accepted. **No " +
		"confidently-wrong output**: only 802.11 / radiotap link types are decoded (105 / 127); a handshake " +
		"is emitted only when a real M1 is paired with a real M2 on a matching replay counter; the MIC field " +
		"is zeroed in the emitted EAPOL frame (as hashcat requires); an incomplete M2's all-zero MIC is " +
		"dropped; and the crackable line is built only once the ESSID has been seen (a handshake with no " +
		"ESSID is reported, with a note, but no line is fabricated).\n\n" +
		"Provide the capture **base64-encoded** (it is binary). Only the **M1+M2** message pair (hashcat " +
		"message_pair 0x00) is extracted; the M2+M3, M1+M4 and M3+M4 pairings are deferred. No network, no " +
		"device, transmits nothing — Low risk. Source: docs/catalog/gap-analysis.md (WiFi PMKID -> hashcat " +
		"22000 pipeline, the type-02 4-way row). Wrap-vs-native: native — orchestration over in-tree " +
		"decoders, no new go.mod dep; anchored to round-trip captures built from the same decoders.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pcap_base64":{"type":"string","description":"The 802.11 packet capture — classic libpcap or pcapng, LINKTYPE 105 / 127 — base64-encoded."}
		},
		"required":["pcap_base64"]
	}`),
	Required:  []string{"pcap_base64"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiEAPOLPcapHandler,
}

func wifiEAPOLPcapHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "pcap_base64"))
	if b64 == "" {
		return "", fmt.Errorf("wifi_eapol_pcap: 'pcap_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("wifi_eapol_pcap: 'pcap_base64' is not valid base64: %w", err)
	}
	res, err := eapolcap.Extract(raw)
	if err != nil {
		return "", fmt.Errorf("wifi_eapol_pcap: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
