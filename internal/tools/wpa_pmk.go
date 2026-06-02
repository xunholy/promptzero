// wpa_pmk.go — host-side WPA/WPA2-PSK Pairwise Master Key derivation Spec,
// delegating to internal/wpa.
//
// Wrap-vs-native: native — the PMK is PBKDF2-HMAC-SHA1(passphrase, SSID, 4096,
// 32) per IEEE 802.11i; PBKDF2 is implemented in-tree over crypto/hmac. It is
// an offline Wi-Fi pentest primitive: turn a candidate passphrase + target SSID
// into the 256-bit PMK an attacker precomputes to test against a captured 4-way
// handshake / PMKID. It supplies the derivation step that wifi_pmkid_hc22000
// (a hashcat-line formatter) and internal/rsn (a PMKID parser) do not. Offline
// compute from operator-supplied strings; no network or device.

package tools

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/wpa"
)

func init() { //nolint:gochecknoinits
	Register(wpaPMKDeriveSpec)
}

var wpaPMKDeriveSpec = Spec{
	Name: "wpa_pmk_derive",
	Description: "Derive the WPA/WPA2-PSK Pairwise Master Key (PMK) from a passphrase and SSID — the " +
		"offline Wi-Fi primitive that turns a candidate passphrase plus the target network name into the " +
		"256-bit PMK. That PMK is what you precompute to test a guess against a captured 4-way handshake or " +
		"PMKID (the basis of the hashcat 22000 / 16800 workflows). Supplies the derivation step that " +
		"wifi_pmkid_hc22000 (which formats a hashcat line) and the RSN/PMKID beacon parser do not.\n\n" +
		"Fields: **passphrase** (8-63 printable-ASCII characters, the IEEE 802.11i constraint) and **ssid** " +
		"(1-32 bytes, the network name). The PMK is PBKDF2-HMAC-SHA1(passphrase, ssid, 4096 iterations, 32 " +
		"bytes); the output is the PMK as hex. The 64-hex raw-PSK form and PMKID computation are out of " +
		"scope.\n\n" +
		"Offline compute from operator-supplied strings — no network, no device, transmits nothing, so it " +
		"is Low risk. Verified in-tree against the RFC 6070 PBKDF2 vectors and the IEEE 802.11i WPA-PSK " +
		"vectors (passphrase \"password\" / SSID \"IEEE\" -> f42c6fc5…). Wrap-vs-native: native — PBKDF2 " +
		"over crypto/hmac + crypto/sha1, standard-library only.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"passphrase":{"type":"string","description":"WPA-PSK passphrase (8-63 printable-ASCII characters)."},
			"ssid":{"type":"string","description":"Network name / SSID (1-32 bytes), used as the PBKDF2 salt."}
		},
		"required":["passphrase","ssid"]
	}`),
	Required:  []string{"passphrase", "ssid"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wpaPMKDeriveHandler,
}

func wpaPMKDeriveHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	passphrase := str(p, "passphrase")
	ssid := str(p, "ssid")
	if passphrase == "" || ssid == "" {
		return "", fmt.Errorf("wpa_pmk_derive: 'passphrase' and 'ssid' are required")
	}
	pmk, err := wpa.DerivePMK(passphrase, ssid)
	if err != nil {
		return "", fmt.Errorf("wpa_pmk_derive: %w", err)
	}
	out, _ := json.MarshalIndent(map[string]any{
		"ssid":       ssid,
		"pmk":        hex.EncodeToString(pmk),
		"pmk_bits":   len(pmk) * 8,
		"kdf":        "PBKDF2-HMAC-SHA1",
		"iterations": 4096,
	}, "", "  ")
	return strings.TrimSpace(string(out)), nil
}
