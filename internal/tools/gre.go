// gre.go — host-side GRE packet decoder Spec.
// Wraps the internal/gre walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/gre"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(greDecodeSpec)
}

var greDecodeSpec = Spec{
	Name: "gre_decode",
	Description: "Decode a Generic Routing Encapsulation (GRE) packet per RFC 2784 " +
		"(base) + RFC 2890 (Key + Sequence Number) + RFC 2637 (PPTP Enhanced GRE, " +
		"Version=1). GRE is the foundational IP-in-IP tunneling protocol — every " +
		"site-to-site VPN, every MPLS-over-GRE deployment, every PPTP client (legacy " +
		"Windows VPNs), every EoGRE (Ethernet-over-GRE) WiFi-controller-to-AP tunnel, " +
		"every Cloudflare/Fastly anycast backbone uses it. Pairs with `vxlan_decode` " +
		"as a sibling tunneling protocol. Decodes:\n\n" +
		"- **4-byte mandatory header** (RFC 2784 §2):\n" +
		"  - **byte 0**: C (Checksum present, bit 7), R (Routing present — deprecated, " +
		"bit 6), K (Key present, bit 5), S (Sequence Number present, bit 4), s " +
		"(Strict Source Route — deprecated, bit 3), Recur (Recursion Control — " +
		"deprecated, bits 0-2).\n" +
		"  - **byte 1**: Flags (5 bits) + Version (3 bits). Version 0 = standard GRE; " +
		"Version 1 = PPTP Enhanced GRE.\n" +
		"  - **bytes 2-3**: Protocol Type (EtherType of the encapsulated payload). " +
		"**8-entry name table**:\n" +
		"    - 0x0800 IPv4\n" +
		"    - 0x86DD IPv6\n" +
		"    - 0x6558 Transparent Ethernet Bridging (EoGRE — L2 tunnel)\n" +
		"    - 0x880B PPP (PPP-in-GRE)\n" +
		"    - 0x8847 MPLS unicast\n" +
		"    - 0x8848 MPLS multicast\n" +
		"    - 0x6559 Raw Frame Relay\n" +
		"    - 0x0806 ARP\n" +
		"- **Optional fields** (gated by flag bits, in this order):\n" +
		"  - If C or R set: **Checksum + Offset** (4 bytes total — Offset is only " +
		"meaningful when R is set; R is deprecated).\n" +
		"  - If K set (RFC 2890): **Key** (4 bytes — used to demultiplex multiple GRE " +
		"tunnels between the same endpoints).\n" +
		"  - If S set (RFC 2890): **Sequence Number** (4 bytes — for in-order " +
		"delivery; rarely used in practice).\n" +
		"- **PPTP Enhanced GRE** (RFC 2637, Version=1) — Microsoft PPTP overloads the " +
		"K bit + Key field: the 4 bytes are split into **PayloadLength** (uint16 BE) " +
		"+ **Call ID** (uint16 BE). PPTP additionally adds an **Acknowledgement " +
		"Number** (4 bytes) when the A bit (bit 7 of byte 1) is set. PPTP always has " +
		"K=1, S is optional, A is optional.\n" +
		"- **Variant classification**: surfaces 'standard GRE (RFC 2784/2890)' for " +
		"V=0 or 'PPTP Enhanced GRE (RFC 2637)' for V=1.\n" +
		"- **Deprecation notes** — surfaces a Note when R (Routing Present) or s " +
		"(Strict Source Route) is set, flagging the RFC 1701 deprecation.\n" +
		"- **Encapsulated payload bytes** are surfaced as hex with a header-bytes " +
		"hint, so operators can pipe the post-GRE bytes to the appropriate decoder " +
		"(`ip_packet_decode` for IPv4/IPv6, a future Ethernet decoder for TEB " +
		"payloads, `arp_decode` for ARP, etc.).\n\n" +
		"Pure offline parser — operators paste IP-payload bytes (IP protocol number " +
		"47 in the outer IP header) from a `tcpdump -X proto 47` line, a Wireshark " +
		"Follow-IP-Stream view, a Cisco IOS `debug tunnel` trace, an OpenStack " +
		"Octavia HM-tunnel capture, or any GRE-emitting tool and get the documented " +
		"header plus encapsulated protocol identification.\n\n" +
		"Out of scope (deferred): IP framing (feed the IP-payload bytes after the " +
		"outer IPv4 / IPv6 header strip — IP protocol number 47 for GRE); inner " +
		"payload decoding (operators pipe the post-GRE bytes to `ip_packet_decode`, " +
		"a future Ethernet decoder for TEB payloads, etc.); Routing field (R bit) " +
		"body (the RFC 1701 routing entries are deprecated and we only surface the " +
		"Checksum + Offset bytes); PPP frame dissection inside PPTP (post-Ack PPP " +
		"frame is a separate Spec).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational IP tunneling protocol — " +
		"pairs with vxlan_decode for the modern overlay-protocol picture). " +
		"Wrap-vs-native: native — RFC 2784/2890/2637 are fully public; wire format " +
		"is a tight bit-packed header with optional fields gated by flag bits; no " +
		"crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"GRE packet bytes (after the outer IP header strip; IP protocol number 47). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   greDecodeHandler,
}

func greDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("gre_decode: 'hex' is required")
	}
	res, err := gre.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("gre_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
