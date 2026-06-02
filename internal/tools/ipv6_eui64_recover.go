// ipv6_eui64_recover.go — host-side IPv6 → MAC (Modified EUI-64) recovery
// Spec, delegating to internal/macaddr.
//
// Wrap-vs-native: native — recovering the MAC embedded in an IPv6 SLAAC
// interface identifier is a fixed transform (detect the FF:FE marker, remove
// it, flip the U/L bit), the inverse of the Modified-EUI-64 construction. It
// is the offline complement to the IPv6 decoders (ndp_decode / dhcpv6_decode
// surface IPv6 addresses): a host whose address was derived from its MAC can
// be deanonymised here. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/macaddr"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ipv6EUI64RecoverSpec)
}

var ipv6EUI64RecoverSpec = Spec{
	Name: "ipv6_eui64_recover",
	Description: "Recover the MAC address embedded in an IPv6 address's interface identifier (the low " +
		"64 bits) when it is a Modified EUI-64 — the SLAAC scheme that derives the address from the " +
		"host's MAC. This deanonymises an IPv6 host: ndp_decode / dhcpv6_decode surface the addresses, " +
		"and this recovers the hardware MAC from them.\n\n" +
		"A Modified EUI-64 is recognised by the FF:FE marker in the middle of the interface identifier; " +
		"the MAC is recovered by removing FF:FE and flipping the U/L bit back. The result is framed as " +
		"an observation, not a certainty — a privacy-extension (RFC 4941), stable-private (RFC 7217), or " +
		"random IID does not carry the marker, and matches it only ~1 in 65536 by chance, in which case " +
		"the tool reports that no MAC is recoverable (no confidently-wrong output). When a MAC is " +
		"recovered it is also classified (unicast/multicast, locally vs universally administered → the " +
		"randomized-MAC signal, OUI) so a recovered randomized SLAAC address is flagged as such.\n\n" +
		"Works on any IPv6 address (link-local fe80:: or global SLAAC). Offline transform — reads a " +
		"string, transmits nothing, so it is Low risk. Wrap-vs-native: native — fixed byte/bit transform, " +
		"the inverse of the EUI-64 construction, no hardware.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"ipv6":{"type":"string","description":"An IPv6 address (link-local or global). Standard textual forms accepted."}
		},
		"required":["ipv6"]
	}`),
	Required:  []string{"ipv6"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ipv6EUI64RecoverHandler,
}

func ipv6EUI64RecoverHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "ipv6")) == "" {
		return "", fmt.Errorf("ipv6_eui64_recover: 'ipv6' is required")
	}
	res, err := macaddr.RecoverMAC(str(p, "ipv6"))
	if err != nil {
		return "", fmt.Errorf("ipv6_eui64_recover: %w", err)
	}
	out := struct {
		*macaddr.EUI64Result
		MACClassification *macaddr.Result `json:"mac_classification,omitempty"`
	}{EUI64Result: res}
	if res.RecoveredMAC != "" {
		if c, cerr := macaddr.Classify(res.RecoveredMAC); cerr == nil {
			out.MACClassification = c
		}
	}
	body, _ := json.MarshalIndent(out, "", "  ")
	return string(body), nil
}
