// etherip_decode.go — host-side EtherIP (RFC 3378, L2-over-IP tunnel)
// decoder Spec, delegating to internal/etherip.
//
// Wrap-vs-native: native — a 2-byte header + an inner Ethernet frame,
// chaining the encapsulated IP to internal/ipdecode; byte-field reads,
// stdlib only. Completes the tunnel-decap family (gre/geneve/vxlan/mpls/
// sflow). Surfaces the tunnelled inner frame + flow. Offline read.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/etherip"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(etherIPDecodeSpec)
}

var etherIPDecodeSpec = Spec{
	Name: "etherip_decode",
	Description: "Decode **EtherIP** (RFC 3378) — the protocol that tunnels a whole **Ethernet frame inside an " +
		"IP packet** (IP protocol 97). Completes the project's tunnel-decap decoder family alongside `gre`, " +
		"`geneve`, `vxlan`, `mpls` and `sflow`: a captured EtherIP packet is an **L2-over-IP tunnel** (used " +
		"for transparent bridging / L2 VPNs, and as a **data-exfiltration / pivot** encapsulation), so " +
		"decoding it surfaces the tunnelled inner Ethernet frame — the **MAC addresses**, the **EtherType**, " +
		"and (when the inner payload is IP) the **encapsulated flow's** addresses / protocol / ports decoded " +
		"in place via the project's IP decoder.\n\n" +
		"Decodes the 2-byte EtherIP header (version, reserved), the inner Ethernet header (dst/src MAC + " +
		"EtherType + name), and chains an IPv4 / IPv6 inner payload to the full IP decode; a non-IP EtherType " +
		"(ARP, VLAN, MPLS, PPPoE, …) leaves the inner frame as raw hex.\n\n" +
		"No confidently-wrong output: the version is required to be 3 (RFC 3378) — a non-EtherIP packet is " +
		"rejected, not mis-decoded; an inner IP payload that fails to parse degrades to an inner_decode_error " +
		"+ raw hex. No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (L2-over-IP tunnel / exfil decap recon). Wrap-vs-native: " +
		"native — a byte-field read + the existing inner-IP decode path, stdlib only, no new go.mod dep. " +
		"Verified field-for-field against scapy's EtherIP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The EtherIP packet (the IP-protocol-97 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   etherIPDecodeHandler,
}

func etherIPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("etherip_decode: 'hex' is required")
	}
	res, err := etherip.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("etherip_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
