// wifi_80211.go — host-side IEEE 802.11 management frame
// dissector Spec, delegating to the internal/ieee80211 package
// for the walker proper.
//
// Wrap-vs-native judgement: IEEE 802.11 is a fully public
// standard. The walker is bit-level decoding over a 24-byte
// MAC header + per-subtype body + Information Element loop.
// Wrapping a FAP for this would add an SD-card install step +
// a firmware-fork dependency for a pure parser. Native delivers
// offline analysis — operators paste a captured frame from
// Marauder / hcxdumptool / aircrack-ng / Wireshark and inspect
// every MAC-layer field without a WiFi adapter attached.
//
// Pairs with the existing wifi_eapol_decode (which handles the
// EAPOL data frames inside the 4-way handshake) — together
// they cover the WiFi management + key-exchange surface.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ieee80211"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(wifi80211DecodeSpec)
}

var wifi80211DecodeSpec = Spec{
	Name: "wifi_80211_decode",
	Description: "Decode an IEEE 802.11 management frame — beacon, probe request/response, " +
		"authentication, association request/response, disassociation, deauthentication. " +
		"Decodes:\n\n" +
		"- **Frame Control** (16 bits): Protocol Version + Type (Management / Control / Data / " +
		"Extension) + Subtype with documented name lookup + ToDS / FromDS / More Fragments / " +
		"Retry / Power Mgt / More Data / Protected Frame / Order flags.\n" +
		"- **MAC header**: 2-byte duration, 6-byte Destination / Source / BSSID addresses, " +
		"12-bit sequence number + 4-bit fragment number.\n" +
		"- **Per-subtype body decode**:\n" +
		"  - Beacon / Probe Response: timestamp + beacon interval + capability info (ESS / " +
		"IBSS / Privacy / Short Preamble / QoS / etc.) + Information Elements\n" +
		"  - Probe Request: Information Elements only\n" +
		"  - Authentication: algorithm + sequence + status code\n" +
		"  - Association Request: capability + listen interval + IEs\n" +
		"  - Association Response: capability + status + IEs\n" +
		"  - Disassociation / Deauthentication: reason code + documented name lookup\n" +
		"- **Information Elements**: walker for SSID (0), Supported Rates (1, 50), DS " +
		"Parameter Set (3, channel), Country (7), RSN (48 — WPA2/WPA3 with version + group / " +
		"pairwise / AKM cipher-suite OUI/type decode), Vendor Specific (221 — OUI + type + " +
		"well-known-vendor name lookup including Microsoft WPA/WPS subtypes).\n\n" +
		"Non-management frames (Type=1 Control, Type=2 Data) decode the MAC header only. " +
		"Pure offline parser — no WiFi adapter required. Pairs with wifi_eapol_decode for the " +
		"key-exchange frames. Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (WiFi decode space). Wrap-vs-native: native — " +
		"IEEE 802.11 is a fully public spec, the walker is ~500 lines of bit-twiddling + " +
		"lookup tables.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded 802.11 management frame (24-byte MAC header + per-subtype body). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifi80211DecodeHandler,
}

func wifi80211DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("wifi_80211_decode: 'hex' is required")
	}
	res, err := ieee80211.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("wifi_80211_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
