// ip_packet.go — host-side IPv4/IPv6 + TCP/UDP/ICMP/ICMPv6
// packet dissector Spec, delegating to the internal/ipdecode
// package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ipdecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ipPacketDecodeSpec)
}

var ipPacketDecodeSpec = Spec{
	Name: "ip_packet_decode",
	Description: "Decode a raw IP packet (IPv4 or IPv6) plus the most-deployed next-layer " +
		"headers (TCP, UDP, ICMP, ICMPv6). Foundational network-decode primitive every other " +
		"application-layer Spec sits on top of — operators routinely paste raw pcap bytes " +
		"that include the IP + transport headers, and pulling those out manually is tedious. " +
		"Per RFC 791 (IPv4) + RFC 8200 (IPv6) + RFC 9293 (TCP) + RFC 768 (UDP) + RFC 792 " +
		"(ICMP) + RFC 4443 (ICMPv6). Decodes:\n\n" +
		"- **IPv4/IPv6 auto-detection** by the first nibble (4 or 6).\n" +
		"- **IPv4 header**: version + IHL + DSCP/ECN broken out of the ToS byte + total " +
		"length + identification + flags (DF / MF) + fragment offset + TTL + protocol " +
		"name (IANA registry) + header checksum + source/destination IPv4 + options hex " +
		"(when IHL > 5).\n" +
		"- **IPv6 header**: version + traffic class (DSCP + ECN broken out) + flow label + " +
		"payload length + next header name + hop limit + source/destination IPv6. Walks " +
		"the extension-header chain (Hop-by-Hop 0, Routing 43, Fragment 44, ESP 50, AH " +
		"51, Destination 60) and surfaces them as a count + list with raw hex; the final " +
		"inner-next-header dispatches to the transport-layer decoder.\n" +
		"- **TCP header**: source/destination port + sequence + ack + data offset + full " +
		"9-bit flag field broken out as named bools (NS / CWR / ECE / URG / ACK / PSH / " +
		"RST / SYN / FIN) + Wireshark-style flags string + window size + checksum + " +
		"urgent pointer + TLV options walker with named decode for EOL / NOP / MSS / " +
		"Window Scale / SACK Permitted / SACK blocks / Timestamps (TSval+TSecr) / TCP " +
		"Fast Open Cookie + remaining payload hex.\n" +
		"- **UDP header**: source/destination port + length + checksum + payload hex.\n" +
		"- **ICMP**: type + code with name lookup for Echo Reply (0) / Destination " +
		"Unreachable (3, with 13 sub-codes including Network/Host/Protocol/Port " +
		"Unreachable / Fragmentation Needed / Admin Prohibited) / Source Quench (4) / " +
		"Redirect (5) / Echo Request (8) / Router Advertisement (9) / Router Solicitation " +
		"(10) / Time Exceeded (11, with sub-codes) / Parameter Problem (12) / Timestamp " +
		"Request/Reply (13/14). Echo Request/Reply (type 0/8) broken out into identifier + " +
		"sequence + payload.\n" +
		"- **ICMPv6**: type + code with name lookup for Destination Unreachable (1, with " +
		"7 sub-codes) / Packet Too Big (2) / Time Exceeded (3) / Parameter Problem (4) / " +
		"Echo Request (128) / Echo Reply (129) / Multicast Listener Query/Report/Done " +
		"(130-132) / NDP types: Router Solicitation (133) / Router Advertisement (134) / " +
		"Neighbor Solicitation (135) / Neighbor Advertisement (136) / Redirect (137). " +
		"Echo Request/Reply broken out into identifier + sequence + payload.\n\n" +
		"Pure offline parser — operators paste a hex blob from Wireshark / tshark / " +
		"tcpdump-raw / a network forensics dump and inspect every layer. Strip Ethernet/" +
		"VLAN/MPLS framing before passing in (the first byte must be a version nibble). " +
		"Pairs with dns_packet_decode / dhcp_packet_decode / snmp_packet_decode / " +
		"ntp_packet_decode / tls_handshake_decode by extracting the inner payload for them.\n\n" +
		"Out of scope (deferred to future iterations): checksum validation (offload / NAT / " +
		"mid-stream re-injection routinely produce broken checksums in legitimate " +
		"captures); IPv4 fragment reassembly (offset / MF / ID surfaced for caller-side " +
		"reassembly); Ethernet / VLAN / MPLS framing (caller strips); GRE / IPSec ESP / " +
		"AH inner-payload (protocol name surfaced, encrypted body raw); deep IPv6 " +
		"extension-header option-list decode (next-header chain walked, option lists raw " +
		"hex).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational network decode space). " +
		"Wrap-vs-native: native — RFC 791 + 8200 + 9293 + 768 + 792 + 4443 are fully " +
		"public, every field is fixed-position, TCP options are a TLV list with named " +
		"dispatch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded IP packet. First nibble determines IPv4 (4) or IPv6 (6). For IPv4: 20+ byte header (more if IHL>5) + transport. For IPv6: 40-byte header + extension headers + transport. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ipPacketDecodeHandler,
}

func ipPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ip_packet_decode: 'hex' is required")
	}
	res, err := ipdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ip_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
