// vxlan.go — host-side VXLAN packet decoder Spec.
// Wraps the internal/vxlan walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vxlan"
)

func init() { //nolint:gochecknoinits
	Register(vxlanDecodeSpec)
}

var vxlanDecodeSpec = Spec{
	Name: "vxlan_decode",
	Description: "Decode a Virtual Extensible LAN (VXLAN) packet per RFC 7348, plus " +
		"per-vendor variants: Cisco's Group-Based Policy (VXLAN-GBP) and the Generic " +
		"Protocol Extension (VXLAN-GPE). VXLAN is the dominant datacenter overlay " +
		"protocol — VMware NSX uses it, OpenStack Neutron uses it, Kubernetes " +
		"Calico/Flannel/Cilium use it, every modern cloud-native SDN rides on it. " +
		"Pairs naturally with `vlan_decode` (for the inner VLAN tags), `arp_decode`, " +
		"`ip_packet_decode`, and the L4 decoders for full overlay visibility. " +
		"Decodes:\n\n" +
		"- **8-byte VXLAN header** (RFC 7348 §5):\n" +
		"  - byte 0: **Flags**. Bit 3 (I-flag, mask 0x08) MUST be 1 in standard VXLAN " +
		"to indicate the VNI is valid; the other 7 bits are reserved and MUST be 0. " +
		"VXLAN-GBP overloads bit 0 as G (Group Policy Applied) and bit 4 as D (Don't " +
		"Learn).\n" +
		"  - bytes 1-3: **Reserved-1** (24 bits, must be 0 in standard VXLAN). " +
		"VXLAN-GBP overloads as 16-bit Group Policy ID (with 8 reserved bits).\n" +
		"  - bytes 4-6: **VNI** (24-bit VXLAN Network Identifier; like a 24-bit VLAN " +
		"ID, 16M possible).\n" +
		"  - byte 7: **Reserved-2** (must be 0 in standard VXLAN). VXLAN-GPE " +
		"overloads as **Next Protocol** with 5-entry name table (1 IPv4 / 2 IPv6 / " +
		"3 Ethernet / 4 NSH / 5 MPLS).\n" +
		"- **Variant classification**:\n" +
		"  - **standard VXLAN (RFC 7348)** — I-flag set, reserved fields zero.\n" +
		"  - **VXLAN-GBP (Cisco Group-Based Policy)** — I-flag set AND G or D flag " +
		"set in byte 0; the middle 16 bits of reserved-1 are interpreted as the " +
		"Group Policy ID.\n" +
		"  - **VXLAN-GPE (Generic Protocol Extension)** — I-flag set AND byte 7 " +
		"non-zero (interpreted as Next Protocol).\n" +
		"  - **non-VXLAN** — I-flag not set; surfaces a Note that this may be a " +
		"malformed frame or a non-VXLAN packet on UDP 4789.\n" +
		"- **RFC 7348 conformance check**: surfaces a Note when the I-flag is not " +
		"set or when reserved bits are non-zero (which the operator can investigate " +
		"as middlebox abuse / non-standard variant / corrupt frame).\n" +
		"- **Inner Ethernet peek** — the bytes after the VXLAN header are the " +
		"encapsulated original Ethernet frame. Surfaces dst MAC + src MAC + " +
		"EtherType with **13-entry name table** for the EtherType (IPv4 / ARP / " +
		"IPv6 / RARP / 802.1Q + 802.1ad VLAN tags / MPLS unicast+multicast / PPPoE " +
		"Discovery+Session / EAPOL / LLDP / MACsec). Operators pipe the post-Ethernet " +
		"bytes to the appropriate decoder.\n\n" +
		"Pure offline parser — operators paste UDP-payload bytes (standard outer " +
		"UDP dest port 4789) from a Wireshark Follow-UDP-Stream view, a " +
		"`tcpdump -X udp port 4789` line, an OpenStack Neutron debug capture, a " +
		"Kubernetes CNI traffic dump, or any VXLAN-emitting tool and get the " +
		"documented header plus the inner Ethernet header peek.\n\n" +
		"Out of scope (deferred): UDP / IP framing (feed the UDP payload bytes); " +
		"inner Ethernet payload decoding beyond the EtherType identification " +
		"(operators pipe the post-header bytes to `vlan_decode` / `ip_packet_decode` " +
		"/ etc.); VXLAN-GPE Next Protocol body dissection (only the Next Protocol " +
		"byte is decoded; the body is the encapsulated IPv4 / IPv6 / Ethernet " +
		"payload); Geneve (RFC 8926 — different overlay with a TLV options block; " +
		"future Spec); VXLAN flooding / BUM replication semantics (per-packet " +
		"decoder, not a session tracker).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational datacenter overlay " +
		"protocol — universal in cloud-native SDN). Wrap-vs-native: native — RFC " +
		"7348 is fully public; wire format is a tight 8-byte header plus the " +
		"encapsulated original Ethernet frame; no crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"VXLAN UDP-payload bytes as hex (the VXLAN header followed by the inner Ethernet frame). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vxlanDecodeHandler,
}

func vxlanDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("vxlan_decode: 'hex' is required")
	}
	res, err := vxlan.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("vxlan_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
