// geneve.go — host-side Geneve packet decoder Spec.
// Wraps the internal/geneve walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/geneve"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(geneveDecodeSpec)
}

var geneveDecodeSpec = Spec{
	Name: "geneve_decode",
	Description: "Decode a Generic Network Virtualization Encapsulation (Geneve) packet " +
		"per RFC 8926. Geneve is the next-generation datacenter overlay protocol — " +
		"VMware NSX-T defaults to it, OVN/OVS supports it natively (and increasingly " +
		"defaults to it), and it's the IETF-blessed successor to VXLAN with extensible " +
		"TLV options for SDN-specific metadata (group policy, source-port hints, etc.). " +
		"Rounds out the overlay-protocol trio with `vxlan_decode` (canonical L2 " +
		"overlay) and `gre_decode` (classic IP-in-IP tunneling). Decodes:\n\n" +
		"- **8-byte fixed header** (RFC 8926 §3.4):\n" +
		"  - byte 0: **Version** (2 bits, currently 0) + **Option Length** (6 bits, " +
		"in 4-byte words; up to 252 bytes of options).\n" +
		"  - byte 1: **O** (OAM packet, bit 7) + **C** (Critical options present, bit " +
		"6) + 6 reserved bits.\n" +
		"  - bytes 2-3: **Protocol Type** (EtherType). 7-entry name table: 0x6558 " +
		"Transparent Ethernet Bridging (canonical for VMware NSX-T / OVN), 0x0800 " +
		"IPv4, 0x86DD IPv6, 0x8847 MPLS unicast, 0x8848 MPLS multicast, 0x894F NSH " +
		"(Network Service Header), 0x0806 ARP.\n" +
		"  - bytes 4-6: **VNI** (24-bit Virtual Network Identifier — like a 24-bit " +
		"VLAN ID, 16M possible).\n" +
		"  - byte 7: **Reserved** (must be 0).\n" +
		"- **TLV options walker** — each option is 4-byte aligned:\n" +
		"  - bytes 0-1: **Option Class** (16-bit BE; IANA assigned).\n" +
		"  - byte 2: **Type** (bit 7 = C critical option flag, bits 0-6 = " +
		"type-within-class).\n" +
		"  - byte 3: Reserved (3 bits) + **Option Length** (5 bits, in 4-byte words; " +
		"max 124 bytes of option data).\n" +
		"  - bytes 4+: **Option Data** (Length × 4 bytes).\n" +
		"- **Option Class name table** (6 well-known entries + range rules): 0x0000 " +
		"Reserved (IETF), 0x0001-0x00FF IETF standardised, 0x0100 Linux / Open " +
		"vSwitch / OVN, 0x0101 VMware (NSX-T), 0x0102 Mellanox / NVIDIA, 0x0103 " +
		"Cisco Systems, 0x0104 Oracle, 0x0105-0xFEFF vendor (PEN-associated), " +
		"0xFF00+ experimental.\n" +
		"- **Inner payload decode** — for Protocol Type 0x6558 (TEB), surface the " +
		"encapsulated dst MAC + src MAC + inner EtherType with **13-entry name " +
		"table** (IPv4 / ARP / IPv6 / RARP / 802.1Q + 802.1ad VLAN tags / MPLS " +
		"unicast+multicast / PPPoE Discovery+Session / EAPOL / LLDP / MACsec), and " +
		"when that EtherType is IPv4/IPv6 **decode the inner L3 packet in place**. " +
		"For Protocol Type 0x0800 / 0x86DD the payload IS an IP packet and is decoded " +
		"directly. Either way the encapsulated flow's addresses / protocol / ports " +
		"surface (a payload that doesn't parse as IP is reported with an error, raw " +
		"hex preserved). Other Protocol Types (MPLS / NSH) stay raw hex.\n" +
		"- **Conformance check** — Version != 0 surfaces a Note (RFC 8926 §5 requires " +
		"dropping); non-zero reserved bits surface a Note; C-flag set surfaces a " +
		"Note explaining that transit nodes MUST process the critical options or " +
		"drop the packet.\n\n" +
		"Pure offline parser — operators paste UDP-payload bytes (standard outer UDP " +
		"dest port 6081) from a Wireshark Follow-UDP-Stream view, a " +
		"`tcpdump -X udp port 6081` line, an OVS / VMware NSX-T debug capture, a " +
		"Kubernetes Antrea / Open vSwitch traffic dump, or any Geneve-emitting tool " +
		"and get the documented header + options + inner protocol identification.\n\n" +
		"Out of scope (deferred): UDP / IP framing (feed UDP payload bytes); non-IP " +
		"inner payloads (802.1Q VLAN tags / MPLS / NSH — left for `vlan_decode` / " +
		"their own decoders); vendor-specific option data " +
		"dissection (only class + type + length surfaced; option data body is hex); " +
		"VXLAN (handled by `vxlan_decode` — Geneve is the more flexible / modern " +
		"alternative but VXLAN remains widely deployed).\n\n" +
		"Source: docs/catalog/gap-analysis.md (next-generation datacenter overlay " +
		"protocol — rounds out the overlay trio with vxlan_decode + gre_decode). " +
		"Wrap-vs-native: native — RFC 8926 is fully public; wire format is a tight " +
		"8-byte fixed header plus TLV options block plus encapsulated payload; no " +
		"crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Geneve UDP-payload bytes as hex (the 8-byte fixed header, followed by TLV options if any, followed by the inner payload). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   geneveDecodeHandler,
}

func geneveDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("geneve_decode: 'hex' is required")
	}
	res, err := geneve.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("geneve_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
