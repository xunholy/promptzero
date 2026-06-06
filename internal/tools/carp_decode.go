// carp_decode.go — host-side Common Address Redundancy Protocol decoder
// Spec, delegating to internal/carp.
//
// Wrap-vs-native: native — a CARP advertisement is a fixed 36-octet
// structure (IP protocol 112, shared with VRRP); byte-field extraction.
// The third FHRP decoder with hsrp + vrrp — decoded for the same
// FHRP-hijacking (MITM) reason. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/carp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(carpDecodeSpec)
}

var carpDecodeSpec = Spec{
	Name: "carp_decode",
	Description: "Decode the **Common Address Redundancy Protocol** (CARP) — the open first-hop-redundancy " +
		"protocol (FHRP) used by **OpenBSD / FreeBSD / pfSense / OPNsense** for gateway / firewall high " +
		"availability. The third FHRP decoder alongside `hsrp_decode` (Cisco HSRP) and `vrrp_decode` (IETF " +
		"VRRP), decoded for the same reason: **FHRP hijacking is a classic on-path (MITM) attack** — a host " +
		"that advertises for the virtual router with a better election metric becomes the master and draws " +
		"the LAN's default-gateway traffic through itself.\n\n" +
		"Decodes the CARP advertisement: **version / type**, the **VHID** (virtual host ID — the redundancy " +
		"group), the **advskew** and **advbase** (and the derived advertisement interval = advbase + " +
		"advskew/256 s), the auth length, demotion, checksum, the 64-bit counter, and the 20-octet SHA-1 " +
		"HMAC. Accepts the CARP PDU itself or an IPv4 packet (protocol 112) whose payload is CARP.\n\n" +
		"**The advskew is the attack signal**: lower skew advertises more frequently and wins the master " +
		"election, so a captured advertisement with a very low / zero advskew is the CARP " +
		"hijack/preemption (MITM) tell — the same FHRP attack class as HSRP priority 255 / VRRP priority " +
		"255. No confidently-wrong output: the 20-octet **HMAC is surfaced as hex and NOT verified** — it is " +
		"an SHA-1 HMAC keyed by the CARP passphrase, which is not on the wire. No network, no device, " +
		"transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (FHRP-hijacking recon — completes the HSRP/VRRP/CARP set). " +
		"Wrap-vs-native: native — fixed 36-octet byte-field extraction, stdlib only, no new go.mod dep. " +
		"Verified field-for-field against scapy's CARP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"A CARP advertisement as hex (36 octets), or an IPv4 packet (protocol 112) whose payload is CARP. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   carpDecodeHandler,
}

func carpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("carp_decode: 'hex' is required")
	}
	res, err := carp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("carp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
