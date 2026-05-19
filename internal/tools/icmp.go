// icmp.go — host-side ICMP / ICMPv6 packet decoder Spec.
// Wraps the internal/icmp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/icmp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(icmpPacketDecodeSpec)
}

var icmpPacketDecodeSpec = Spec{
	Name: "icmp_packet_decode",
	Description: "Decode an ICMP (RFC 792) or ICMPv6 (RFC 4443 + RFC 4861 for Neighbor " +
		"Discovery) packet. ICMP is the foundational error-and-diagnostic signalling " +
		"layer of every IP network — every ping, every traceroute hop, every TTL " +
		"expiry, every IPv6 SLAAC / neighbor-discovery exchange flows through it. " +
		"Natural companion to `ip_packet_decode` (which strips the IP header and " +
		"leaves you with the ICMP bytes). Decodes:\n\n" +
		"- **Auto-detect ICMPv4 vs ICMPv6** — the `version` parameter is honoured " +
		"when specified ('v4' or 'v6'); otherwise heuristic: types ≥ 128 are ICMPv6 " +
		"(echo + NDP + MLD live there); types 1-30 default to ICMPv4 (where they " +
		"collide on Destination Unreachable / Time Exceeded the v4 interpretation is " +
		"chosen as the more common one). For ambiguous v6 types like 2 (Packet Too " +
		"Big in v6 vs Source Quench in v4), the operator should pass the hint.\n" +
		"- **Common 4-byte header**: Type + Code + Checksum (BE). Checksum is " +
		"surfaced as hex; verification requires the IPv6 pseudo-header (out of scope " +
		"at this layer).\n" +
		"- **ICMPv4 types** (17 entries with code sub-tables): 0 Echo Reply, 3 " +
		"Destination Unreachable (16 codes: Network/Host/Protocol/Port Unreachable, " +
		"Fragmentation Needed and DF set, etc.), 5 Redirect (4 codes), 8 Echo " +
		"Request, 11 Time Exceeded (TTL Expired / Fragment Reassembly Time Exceeded), " +
		"12 Parameter Problem, 13/14 Timestamp Request/Reply, 17/18 Address Mask " +
		"Request/Reply, plus deprecated types (Source Quench, Information " +
		"Request/Reply, Traceroute).\n" +
		"- **ICMPv6 types** (RFC 4443 + 4861 + 3810): 1 Destination Unreachable " +
		"(8 codes), 2 Packet Too Big, 3 Time Exceeded, 4 Parameter Problem (4 codes), " +
		"128/129 Echo Request/Reply, 130-132 MLD, 133 Router Solicitation, 134 " +
		"Router Advertisement, 135 Neighbor Solicitation, 136 Neighbor Advertisement, " +
		"137 Redirect, 143 MLDv2.\n" +
		"- **Per-type body decoding**:\n" +
		"  - **Echo Request/Reply** (v4 type 8/0, v6 type 128/129): Identifier (uint16 " +
		"BE) + Sequence (uint16 BE) + Data (raw bytes). Identifier+Sequence are how " +
		"`ping` correlates request/reply pairs.\n" +
		"  - **Destination Unreachable / Time Exceeded / Parameter Problem** (v4): " +
		"'unused' field + embedded original IP packet (header + 8 bytes of payload) " +
		"surfaced as hex for re-feed into `ip_packet_decode`.\n" +
		"  - **Redirect** (v4 type 5): Gateway IPv4 address + embedded original " +
		"packet.\n" +
		"  - **Packet Too Big** (v6 type 2): MTU (uint32) + embedded original IPv6 " +
		"packet.\n" +
		"  - **Neighbor Solicitation / Advertisement** (v6 type 135 / 136): Target " +
		"Address (16 bytes formatted as IPv6) + NA-flags (R Router / S Solicited / O " +
		"Override) + Options (NDP TLV walker per RFC 4861 §4 — type + length-in-units-" +
		"of-8 + value).\n" +
		"  - **Router Advertisement** (v6 type 134): Cur Hop Limit + Flags (M Managed " +
		"Address Config / O Other Config / H Mobile IPv6 Home Agent) + Router " +
		"Lifetime + Reachable Time + Retrans Timer + Options.\n" +
		"  - **Router Solicitation** (v6 type 133): Options only.\n" +
		"- **NDP options** — TLV walker with 9-entry name table: 1 Source Link-Layer " +
		"Address, 2 Target Link-Layer Address, 3 Prefix Information, 4 Redirected " +
		"Header, 5 MTU, 14 Nonce (SEND), 24 Route Information, 25 Recursive DNS " +
		"Server (RDNSS), 31 DNS Search List (DNSSL). Option body bytes surfaced as " +
		"hex; sub-fields (e.g. Prefix Information's full layout) belong in a deeper " +
		"helper.\n\n" +
		"Pure offline parser — operators paste ICMP bytes from a Wireshark " +
		"Follow-IP-Stream view, a `tcpdump -X icmp` line, an `iptables -j LOG` capture, " +
		"or any packet capture and inspect every documented field. Pairs with " +
		"`ip_packet_decode` (which already strips the IP header) for the complete " +
		"IP+ICMP decode flow.\n\n" +
		"Out of scope (deferred): IPv4 / IPv6 header parsing (handled by " +
		"`ip_packet_decode`); checksum verification (would require the IPv6 pseudo-" +
		"header for v6); MLD / MLDv2 group-record dissection (only type name surfaced); " +
		"per-NDP-option deep parsing beyond the name (e.g. Prefix Information's full " +
		"layout — surfaced as raw hex).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational network-layer diagnostic " +
		"protocol). Wrap-vs-native: native — both RFC 792 and RFC 4443 are fully " +
		"public; wire format is a tight fixed-layout header with a small per-type " +
		"body catalogue.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"ICMP / ICMPv6 packet bytes as hex (after IP header strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."},
			"version":{"type":"string","description":"Optional protocol version hint: 'v4' or 'v6'. When omitted, auto-detected by type byte (≥128 → v6, else v4). Pass explicitly for ambiguous types (e.g. type 2 is v4 Source Quench vs v6 Packet Too Big)."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   icmpPacketDecodeHandler,
}

func icmpPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("icmp_packet_decode: 'hex' is required")
	}
	version := strings.TrimSpace(str(p, "version"))
	res, err := icmp.Decode(raw, version)
	if err != nil {
		return "", fmt.Errorf("icmp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
