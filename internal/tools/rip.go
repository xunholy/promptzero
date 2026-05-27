// rip.go — host-side RIP v1/v2 wire-protocol decoder Spec.
// Wraps the internal/rip walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/rip"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ripDecodeSpec)
}

var ripDecodeSpec = Spec{
	Name: "rip_decode",
	Description: "Decode a RIP (Routing Information Protocol) v1 or v2 UDP payload per " +
		"RFC 1058 (RIPv1) and RFC 2453 (RIPv2). RIP runs on UDP/520 and is one of the " +
		"oldest distance-vector routing protocols — still widely deployed in legacy " +
		"enterprise networks, campus LANs, ISP last-mile, and embedded routers.\n\n" +
		"**Security relevance** — RIP is a critical pentest and network-forensics target:\n\n" +
		"- **RIPv1 has NO authentication** — any host on the subnet can inject arbitrary " +
		"routes. Forged Response packets redirect traffic through attacker-controlled " +
		"routers with no cryptographic barrier.\n" +
		"- **RIPv2 simple-password auth (type 2) transmits the password in CLEARTEXT** " +
		"inside the authentication entry (address_family = 0xFFFF). A single passive " +
		"capture yields the shared secret immediately.\n" +
		"- **RIPv2 MD5 auth (type 3)** is offline-crackable via captured challenge/response.\n" +
		"- **Route injection** — announce any prefix with metric 1 (including 0.0.0.0/0) " +
		"to become the default gateway for the entire broadcast domain.\n" +
		"- **Black-hole attack** — send metric=16 (infinity) for a victim prefix to " +
		"trigger route withdrawal and black-hole traffic for that destination.\n" +
		"- **Topology disclosure** — every RIP Response enumerates internal prefixes, " +
		"subnet masks (v2), and next-hop addresses; free network recon with no active probe.\n\n" +
		"Decodes:\n\n" +
		"- **4-byte RIP header**: command (1 = Request / 2 = Response) + version " +
		"(1 = RIPv1 / 2 = RIPv2) + reserved/zero (2 bytes).\n" +
		"- **20-byte route entries** (up to first 10 entries surfaced): address_family " +
		"(2 BE; 2 = AF_INET, 0xFFFF = auth marker) + route_tag (2 BE; RIPv2 only) + " +
		"ip_address (4 bytes, dotted-quad) + subnet_mask (4 bytes; RIPv2 only) + " +
		"next_hop (4 bytes; RIPv2 only) + metric (4 BE; 1-15 valid, 16 = infinity).\n" +
		"- **RIPv2 authentication entry** (address_family = 0xFFFF): auth_type " +
		"(2 = simple password cleartext / 3 = MD5) + 16-byte auth data.\n" +
		"- **Security flags**: is_cleartext_auth (simple-password type 2 flagged with " +
		"descriptive message) + has_infinity_metric (metric=16 present — route " +
		"withdrawal / black-hole indicator) + has_auth / is_request / is_response.\n" +
		"- route_count (authentication entries excluded from count).\n\n" +
		"Pure offline parser — paste RIP UDP payload bytes (port 520) from tcpdump " +
		"(`tcpdump -w - udp port 520`) or a Wireshark RIP dissector and get a complete " +
		"per-packet breakdown including route enumeration, auth detection, and cleartext-" +
		"password flagging.\n\n" +
		"Out of scope: RIPng (IPv6, UDP/521 — different header layout and address sizes); " +
		"RIPv2 MD5 digest verification (key ID and sequence number are surfaced; the " +
		"HMAC-MD5 computation itself requires the pre-shared key); LSA-equivalent deep " +
		"route-body parsing (prefix/mask/nexthop surfaced as dotted-quad strings; no " +
		"CIDR aggregation or route-table reconstruction).\n\n" +
		"Source: gap analysis (legacy interior routing protocol — pentest primitive for " +
		"route injection, cleartext credential exposure, and topology enumeration; pairs " +
		"with ospf_packet_decode and bgp_message_decode for complete routing-protocol " +
		"coverage). Wrap-vs-native: native — RFC 1058 and RFC 2453 are fully public; " +
		"wire format is a 4-byte header plus 20-byte fixed-size entries; no crypto at " +
		"the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"RIP v1/v2 UDP payload bytes as hex (port 520; the UDP datagram payload after stripping the 8-byte UDP header). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ripDecodeHandler,
}

func ripDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("rip_decode: 'hex' is required")
	}
	res, err := rip.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("rip_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
