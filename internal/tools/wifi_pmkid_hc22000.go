// wifi_pmkid_hc22000.go — host-side native hashcat mode-22000 PMKID line
// builder, delegating to internal/hashcat.
//
// Wrap-vs-native: native — the canonical pcap → .hc22000 converter
// (hcxpcapngtool) is a third-party C binary that marauder_handoff_hashcat
// shells out to. The 22000 PMKID LINE FORMAT is a short deterministic
// "*"-delimited text record needing no external binary once the operator
// holds the fields; this builds it natively, removing the dependency for
// the clientless-PMKID case. Anchored on hashcat's published example hash.

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
	Register(wifiPMKIDHC22000Spec)
}

var wifiPMKIDHC22000Spec = Spec{
	Name: "wifi_pmkid_hc22000",
	Description: "Build a hashcat mode-22000 PMKID line natively from a clientless-PMKID capture — no " +
		"hcxpcapngtool / hcxtools required (the format is assembled in pure Go). PMKID is the dominant " +
		"modern WPA/WPA2 capture: a single frame from the AP yields a crackable hash without any " +
		"client handshake. Feed the PMKID + the two MACs + the ESSID an operator already holds (from " +
		"wifi_eapol_decode, a Marauder sniffpmkid run, or any capture) and get the ready-to-crack " +
		"line back.\n\n" +
		"Output line shape: WPA*01*<pmkid>*<ap_mac>*<sta_mac>*<essid_hex>*** (the three trailing " +
		"ANONCE/EAPOL/MESSAGEPAIR fields are empty for a PMKID record). Write it to a .hc22000 file " +
		"and crack with `hashcat -m 22000`.\n\n" +
		"Fields: **pmkid** (16 bytes / 32 hex), **ap_mac** + **sta_mac** (6 bytes each; separators " +
		"and 0x tolerated), and the network name as either **essid** (UTF-8 string) or **essid_hex** " +
		"(raw hex). A malformed field is rejected rather than emitted, so the line never silently " +
		"fails to crack. Pure host-side — no capture, no radio. For the **client-handshake** case use " +
		"`wifi_eapol_hc22000` (the type-02 EAPOL line builder). Wrap-vs-native: native — a documented " +
		"text format, no external binary, anchored on hashcat's published 22000 example.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"pmkid":{"type":"string","description":"PMKID, 16 bytes / 32 hex chars. Separators / 0x tolerated."},
			"ap_mac":{"type":"string","description":"Access-point (BSSID) MAC, 6 bytes / 12 hex. Separators tolerated."},
			"sta_mac":{"type":"string","description":"Station (client) MAC, 6 bytes / 12 hex. Separators tolerated."},
			"essid":{"type":"string","description":"Network name as a UTF-8 string (1..32 bytes). Use this OR essid_hex."},
			"essid_hex":{"type":"string","description":"Network name as raw hex (overrides essid). Use when the SSID has non-UTF-8 bytes."}
		},
		"required":["pmkid","ap_mac","sta_mac"]
	}`),
	Required:  []string{"pmkid", "ap_mac", "sta_mac"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiPMKIDHC22000Handler,
}

func wifiPMKIDHC22000Handler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	pmkid := str(p, "pmkid")
	apMAC := str(p, "ap_mac")
	staMAC := str(p, "sta_mac")
	if strings.TrimSpace(pmkid) == "" || strings.TrimSpace(apMAC) == "" || strings.TrimSpace(staMAC) == "" {
		return "", fmt.Errorf("wifi_pmkid_hc22000: 'pmkid', 'ap_mac', and 'sta_mac' are all required")
	}

	var essid []byte
	if eh := strings.TrimSpace(str(p, "essid_hex")); eh != "" {
		clean := strings.NewReplacer(" ", "", ":", "", "-", "", "_", "").Replace(eh)
		clean = strings.TrimPrefix(strings.TrimPrefix(clean, "0x"), "0X")
		b, err := hex.DecodeString(clean)
		if err != nil {
			return "", fmt.Errorf("wifi_pmkid_hc22000: essid_hex is not valid hex: %w", err)
		}
		essid = b
	} else {
		essid = []byte(str(p, "essid"))
	}

	line, err := hashcat.PMKID(pmkid, apMAC, staMAC, essid)
	if err != nil {
		return "", fmt.Errorf("wifi_pmkid_hc22000: %w", err)
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
