// wifi_rsn.go — host-side RSN (WPA2/WPA3) Information Element dissector
// Spec, delegating to the internal/rsn package.
//
// Wrap-vs-native: native — the RSNE layout + the 00-0F-AC suite numbers
// are a public IEEE standard (802.11-2020 §9.4.2.24). The wifi_80211
// decoder surfaces raw suite OUIs but, by its own note, leaves naming +
// the PMF capability bits to a follow-on Spec; this is that Spec.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rsn"
)

func init() { //nolint:gochecknoinits
	Register(wifiRSNDecodeSpec)
}

var wifiRSNDecodeSpec = Spec{
	Name: "wifi_rsn_decode",
	Description: "Decode an 802.11 RSN (WPA2/WPA3) Information Element into named cipher and AKM " +
		"suites, the management-frame-protection (PMF) state, and a derived security posture — the " +
		"security-triage readout for an AP. The wifi_80211 decoder surfaces the raw RSN suite OUIs " +
		"(e.g. 000FAC-04) but leaves naming + the capability bits to a follow-on tool; this is that " +
		"tool.\n\n" +
		"Surfaces:\n" +
		" - **group_cipher** + **pairwise_ciphers** + **akm_suites**, each named per the standard " +
		"00-0F-AC assignments (CCMP-128 / GCMP-256 / TKIP / WEP-… ciphers; PSK / SAE / 802.1X / OWE / " +
		"SuiteB / FT-… AKMs).\n" +
		" - **pmf_required** + **pmf_capable** (the decisive bits: PMF-required blocks classic " +
		"deauth-flood and mitigates KRACK), plus preauth.\n" +
		" - **security** — a derived posture: WPA2-Personal (PSK) / WPA3-Personal (SAE) / WPA3-Personal " +
		"transition (SAE + PSK) / WPA2-WPA3-Enterprise (802.1X) / WPA3-Enterprise 192-bit / Enhanced " +
		"Open (OWE).\n" +
		" - optional **group_mgmt_cipher** (BIP-*, present with PMF) and **pmkid_count**.\n\n" +
		"Accepts the bare RSNE body (starting at the 2-byte version) or the full Information Element " +
		"(element ID 0x30 + length + body); the IE header is stripped. Only standard-OUI suite numbers " +
		"are named — a vendor-OUI or unassigned suite is surfaced raw, never guessed; a truncated " +
		"element yields the fields parsed so far with a note. ':' / '-' / '_' / whitespace separators " +
		"tolerated.\n\n" +
		"Pure offline parser — no WiFi adapter required. Companion to wifi_80211 / wifi_wps_decode. " +
		"Wrap-vs-native: native — public RSNE layout + suite tables, a short walker, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded RSN element. Accepts the bare RSNE body (version-first) or the full element (0x30 <len> ...). Separators / 0x tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   wifiRSNDecodeHandler,
}

func wifiRSNDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("wifi_rsn_decode: 'hex' is required")
	}
	res, err := rsn.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("wifi_rsn_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
