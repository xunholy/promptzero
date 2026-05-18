// wifi_eapol.go — host-side EAPOL-Key frame dissector Spec,
// delegating to the internal/eapol package for the walker proper.
//
// Wrap-vs-native judgement: EAPOL is an IEEE standard (802.1X
// for the L2 frame, 802.11i for the Key descriptor format). The
// walker is bit-level decoding over a 95+ byte frame. Wrapping a
// FAP for this would add an SD-card install step + a
// firmware-fork dependency for a pure parser. Native delivers
// offline analysis — operators paste a captured EAPOL frame from
// tcpdump / Wireshark / hcxdumptool / Marauder and inspect every
// field without a WiFi adapter attached.
//
// Pairs with marauder_handoff_hashcat (which converts captured
// frames to hashcat .hc22000) — this Spec lets operators
// inspect the handshake messages before / after that conversion.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/eapol"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(wifiEAPOLDecodeSpec)
}

var wifiEAPOLDecodeSpec = Spec{
	Name: "wifi_eapol_decode",
	Description: "Decode a captured 802.1X EAPOL-Key frame (the WPA / WPA2 / WPA3 4-way " +
		"handshake) into its structured fields:\n\n" +
		"- **802.1X header**: version (1=WPA1, 2=WPA2, 3=802.1X-2010), frame type, body " +
		"length.\n" +
		"- **Descriptor type**: 1 (RC4 / WPA1) or 2 (RSN / WPA2 / WPA3).\n" +
		"- **Key Information bitfield**: descriptor version (TKIP / CCMP / AES-CMAC for PMF), " +
		"key type (Pairwise PTK or Group GTK), and the Install / Ack / MIC / Secure / Error / " +
		"Request / Encrypted-Key-Data / SMK flags.\n" +
		"- **Handshake message identification**: M1 (Ack=1 MIC=0), M2 (Ack=0 MIC=1 Secure=0), " +
		"M3 (Ack=1 MIC=1 Install=1), or M4 (Ack=0 MIC=1 Secure=1).\n" +
		"- **Key fields**: Key Length, 8-byte Replay Counter, 32-byte Key Nonce " +
		"(ANonce / SNonce), 16-byte Key IV, 8-byte Key RSC, 16-byte Key MIC.\n" +
		"- **Key Data**: when not encrypted, the Key Data Encapsulation (KDE) walker " +
		"decodes embedded elements — RSN IE (element 0x30), GTK KDE, MAC address KDE, PMKID, " +
		"IGTK, etc.\n\n" +
		"Pure offline parser — no Flipper / WiFi adapter required. Pairs with " +
		"marauder_handoff_hashcat (which converts captured EAPOL frames to hashcat .hc22000); " +
		"this Spec lets operators inspect the handshake messages before / after that " +
		"conversion. Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (WiFi decode space adjacent to rank 7 " +
		"wifi_pmkid_capture). Wrap-vs-native: native — EAPOL is a fully public IEEE spec, " +
		"the walker is ~300 lines of bit-twiddling.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded EAPOL frame (4-byte 802.1X header + EAPOL-Key body). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiEAPOLDecodeHandler,
}

func wifiEAPOLDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("wifi_eapol_decode: 'hex' is required")
	}
	res, err := eapol.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("wifi_eapol_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
