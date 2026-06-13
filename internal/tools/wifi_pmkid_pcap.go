// wifi_pmkid_pcap.go — host-side native PMKID-from-pcap extractor Spec,
// delegating to internal/pmkidcap.
//
// Wrap-vs-native: native — composes the in-tree pcap reader, the DS-bit-correct
// 802.11 frame parser, the EAPOL-Key dissector, and the mode-22000 line builder;
// no external binary. Removes the hcxpcapngtool shell-out for the dominant
// clientless-PMKID case on a libpcap or pcapng capture. Offline; no network or
// device.

package tools

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pmkidcap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(wifiPMKIDPcapSpec)
}

var wifiPMKIDPcapSpec = Spec{
	Name: "wifi_pmkid_pcap",
	Description: "Extract **WPA/WPA2 PMKID** hashes from an **802.11 packet capture** and emit ready-to-crack " +
		"hashcat mode-22000 lines — **natively, no hcxpcapngtool**. The clientless PMKID attack is the dominant " +
		"modern WPA2 capture: a single EAPOL **message-1** frame from the AP carries the PMKID in an RSN PMKID " +
		"KDE, so a crackable hash is recovered with **no client handshake**. This walks the capture, pairs each " +
		"PMKID with the network's ESSID (from a beacon / probe-response / association-request), and builds the " +
		"`WPA*01*…` line for each — completing the native pipeline `wifi_pmkid_hc22000` started.\n\n" +
		"It composes the in-tree decoders: the pcap reader, the **DS-bit-correct** 802.11 frame parser (so the " +
		"AP BSSID and station MAC are right), the EAPOL-Key dissector, and the mode-22000 line builder " +
		"(anchored on hashcat's published example). Both **classic libpcap** and **pcapng** (the format Marauder " +
		"/ hcxdumptool actually write) are accepted. **No confidently-wrong output**: only 802.11 / radiotap " +
		"link types are decoded (105 / 127); a PMKID is taken only from an EAPOL message-1 with **unencrypted** " +
		"key data and a 16-byte " +
		"RSN PMKID KDE; the **all-zero** PMKID hostapd sends when none is available is **dropped**; and the " +
		"crackable line is built only once the ESSID has been seen (a PMKID with no ESSID is reported, with a " +
		"note, but no line is fabricated). No network, no device, transmits nothing — Low risk.\n\n" +
		"Provide the capture **base64-encoded** (it is binary). Source: docs/catalog/gap-analysis.md (WiFi " +
		"PMKID → hashcat 22000 pipeline). Wrap-vs-native: native — orchestration over in-tree decoders + a " +
		"fixed LLC/SNAP + EtherType check, no new go.mod dep; anchored to round-trip captures built from the " +
		"same decoders. EAPOL 4-way (type-02) handshake extraction is deferred (needs M1–M4 pairing).",
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
	Handler:   wifiPMKIDPcapHandler,
}

func wifiPMKIDPcapHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	b64 := strings.TrimSpace(str(p, "pcap_base64"))
	if b64 == "" {
		return "", fmt.Errorf("wifi_pmkid_pcap: 'pcap_base64' is required")
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("wifi_pmkid_pcap: 'pcap_base64' is not valid base64: %w", err)
	}
	res, err := pmkidcap.Extract(raw)
	if err != nil {
		return "", fmt.Errorf("wifi_pmkid_pcap: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
