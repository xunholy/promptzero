// mac_classify.go — host-side MAC-address classifier Spec, delegating to
// internal/macaddr and layering the existing known-attack-OUI lookup.
//
// Wrap-vs-native: native — classifying a MAC is two IEEE 802 bit tests
// (I/G multicast, U/L locally-administered) plus a broadcast check, fixed and
// unambiguous. It is the offline analysis complement to the WiFi/BLE scan
// tools, whose results are lists of MACs: the U/L bit flags a randomized /
// privacy MAC (the modern client-MAC-randomization signal), which matters for
// device counting, tracking-resistance, and deauth targeting. Offline read,
// no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/defense"
	"github.com/xunholy/promptzero/internal/macaddr"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(macClassifySpec)
}

var macClassifySpec = Spec{
	Name: "mac_classify",
	Description: "Classify an IEEE 802 MAC address from its administration bits — the offline analysis " +
		"complement to the WiFi/BLE scan tools, whose results are lists of MACs. Reports unicast vs " +
		"multicast (the I/G bit), universally vs locally administered (the U/L bit), and broadcast, all " +
		"of which are exact IEEE 802 facts.\n\n" +
		"The headline signal is randomized_likely: a locally-administered unicast address is the hallmark " +
		"of a randomized / privacy MAC (modern iOS / Android / Windows / Linux randomize the client MAC), " +
		"which matters for counting unique devices, assessing tracking-resistance, and deauth targeting. " +
		"This is framed as an observation, not a verdict (a device can be locally administered for other " +
		"reasons). The OUI (first 3 octets) is surfaced only for a universally-administered address, and " +
		"cross-checked against the curated known-attack-vehicle OUI list (e.g. known rogue-AP / pentest " +
		"hardware vendors) — a match is noted. A full IEEE OUI-to-vendor name is not guessed (no " +
		"confidently-wrong output).\n\n" +
		"Accepts ':' / '-' / '.' / no separators, case-insensitive. Offline transform — reads a string, " +
		"transmits nothing, so it is Low risk. Wrap-vs-native: native — bit math over a 6-byte address.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"mac":{"type":"string","description":"48-bit MAC address. ':' / '-' / '.' / no separators tolerated; case-insensitive."}
		},
		"required":["mac"]
	}`),
	Required:  []string{"mac"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   macClassifyHandler,
}

func macClassifyHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "mac")) == "" {
		return "", fmt.Errorf("mac_classify: 'mac' is required")
	}
	res, err := macaddr.Classify(str(p, "mac"))
	if err != nil {
		return "", fmt.Errorf("mac_classify: %w", err)
	}
	out := struct {
		*macaddr.Result
		KnownAttackVendor string `json:"known_attack_vendor,omitempty"`
	}{Result: res}
	// Only meaningful for a universally-administered (real OUI) address.
	if res.UniversallyAdministered {
		if v := defense.LookupOUI(res.MAC); v != "" {
			out.KnownAttackVendor = v
			res.Notes = append(res.Notes, "OUI matches a curated known-attack-vehicle vendor: "+v)
		}
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
