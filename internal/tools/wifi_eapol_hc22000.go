// wifi_eapol_hc22000.go — host-side native hashcat mode-22000 EAPOL
// 4-way-handshake line builder, delegating to internal/hashcat.
//
// Wrap-vs-native: native — the type-02 .hc22000 LINE FORMAT is a documented
// "*"-delimited text record; this assembles it in pure Go from a decoded
// handshake's fields, removing the hcxpcapngtool shell-out for the
// field-in-hand case. Anchored on hashcat's published mode-22000 EAPOL example.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/hashcat"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(wifiEAPOLHC22000Spec)
}

var wifiEAPOLHC22000Spec = Spec{
	Name: "wifi_eapol_hc22000",
	Description: "Build a hashcat mode-22000 **EAPOL 4-way-handshake** line (type 02) natively from a decoded " +
		"WPA/WPA2 handshake — no hcxpcapngtool / hcxtools required (the format is assembled in pure Go). " +
		"This is the **client-handshake** counterpart of `wifi_pmkid_hc22000`: when you have captured a " +
		"4-way handshake (e.g. via a Marauder sniff + `wifi_eapol_decode`) rather than a clientless PMKID, " +
		"feed the decoded fields and get the ready-to-crack line back.\n\n" +
		"Output line shape: `WPA*02*<mic>*<ap_mac>*<sta_mac>*<essid_hex>*<anonce>*<eapol>*<message_pair>`. " +
		"Write it to a `.hc22000` file and crack with `hashcat -m 22000`.\n\n" +
		"Fields: **mic** (16 bytes / 32 hex — the key MIC from the handshake), **ap_mac** + **sta_mac** " +
		"(6 bytes each; separators and 0x tolerated), the network name as **essid** (UTF-8) or **essid_hex** " +
		"(raw hex), **anonce** (32 bytes — the AP nonce from message 1), **eapol** (the EAPOL frame bytes, " +
		"1..256 bytes hex — the message whose MIC is being attacked, MIC field zeroed), and **message_pair** " +
		"(1 byte — hashcat's M1/M2/M3/M4 pairing + flags). A malformed field is rejected rather than emitted, " +
		"so the line never silently fails to crack. Pure host-side — no capture, no radio. The pcapng " +
		"*parsing* that extracts these fields from a raw capture remains hcxpcapngtool's job; this assembles " +
		"the line once they are in hand. Wrap-vs-native: native — a documented text format, no external " +
		"binary, anchored on hashcat's published 22000 EAPOL example.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"mic":{"type":"string","description":"Key MIC, 16 bytes / 32 hex. Separators / 0x tolerated."},
			"ap_mac":{"type":"string","description":"Access-point (BSSID) MAC, 6 bytes / 12 hex. Separators tolerated."},
			"sta_mac":{"type":"string","description":"Station (client) MAC, 6 bytes / 12 hex. Separators tolerated."},
			"anonce":{"type":"string","description":"AP nonce (from EAPOL message 1), 32 bytes / 64 hex."},
			"eapol":{"type":"string","description":"EAPOL frame bytes (the MIC-bearing message, MIC zeroed), 1..256 bytes hex."},
			"message_pair":{"type":"string","description":"hashcat message-pair byte, 1 byte / 2 hex (e.g. a2)."},
			"essid":{"type":"string","description":"Network name as a UTF-8 string (1..32 bytes). Use this OR essid_hex."},
			"essid_hex":{"type":"string","description":"Network name as raw hex (overrides essid). Use when the SSID has non-UTF-8 bytes."}
		},
		"required":["mic","ap_mac","sta_mac","anonce","eapol","message_pair"]
	}`),
	Required:  []string{"mic", "ap_mac", "sta_mac", "anonce", "eapol", "message_pair"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiEAPOLHC22000Handler,
}

func wifiEAPOLHC22000Handler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	mic := str(p, "mic")
	apMAC := str(p, "ap_mac")
	staMAC := str(p, "sta_mac")
	anonce := str(p, "anonce")
	eapol := str(p, "eapol")
	mp := str(p, "message_pair")
	for name, v := range map[string]string{"mic": mic, "ap_mac": apMAC, "sta_mac": staMAC, "anonce": anonce, "eapol": eapol, "message_pair": mp} {
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("wifi_eapol_hc22000: %q is required", name)
		}
	}

	var essid []byte
	if eh := strings.TrimSpace(str(p, "essid_hex")); eh != "" {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(eh)
		clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("wifi_eapol_hc22000: essid_hex is not valid hex: %w", err)
		}
		essid = b
	} else {
		essid = []byte(str(p, "essid"))
	}

	line, err := hashcat.EAPOL(mic, apMAC, staMAC, essid, anonce, eapol, mp)
	if err != nil {
		return "", fmt.Errorf("wifi_eapol_hc22000: %w", err)
	}
	out, _ := json.MarshalIndent(struct {
		HC22000Line    string `json:"hc22000_line"`
		HashcatCommand string `json:"hashcat_command"`
	}{
		HC22000Line:    line,
		HashcatCommand: "hashcat -m 22000 -a 0 capture.hc22000 wordlist.txt",
	}, "", "  ")
	return string(out), nil
}
