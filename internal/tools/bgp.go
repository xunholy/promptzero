// bgp.go — host-side BGP-4 message decoder Spec.
// Wraps the internal/bgp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/bgp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(bgpMessageDecodeSpec)
}

var bgpMessageDecodeSpec = Spec{
	Name: "bgp_message_decode",
	Description: "Decode a BGP-4 message per RFC 4271 plus the canonical extensions: " +
		"RFC 4760 (Multiprotocol BGP / MP-BGP), RFC 5492 (Capabilities Optional " +
		"Parameter), RFC 6793 (4-byte AS Number), and RFC 2918 / 7313 (Route " +
		"Refresh). BGP-4 is the foundational inter-AS routing protocol that runs the " +
		"public Internet — every ISP backbone, every CDN edge, every cloud provider " +
		"network, every hyperscaler peer speaks BGP. Decodes:\n\n" +
		"- **19-byte fixed header** (RFC 4271 §4.1):\n" +
		"  - bytes 0-15: **Marker** — MUST be 16 bytes of 0xFF. Non-conformant " +
		"markers surface a Note (the all-ones requirement is a relic of the BGP-3 " +
		"authentication scheme that BGP-4 keeps for protocol fidelity).\n" +
		"  - bytes 16-17: **Length** (uint16 BE) — total message length including " +
		"the 19-byte header. Range 19-4096 (or up to 65535 with RFC 8654 BGP-EXT).\n" +
		"  - byte 18: **Type** with **5-entry name table**: 1 OPEN, 2 UPDATE, " +
		"3 NOTIFICATION, 4 KEEPALIVE, 5 ROUTE-REFRESH.\n" +
		"- **OPEN body** (RFC 4271 §4.2): Version (1 byte; 4) + My AS (uint16 BE; " +
		"23456 = AS_TRANS for 4-byte AS) + Hold Time (uint16 BE seconds) + BGP " +
		"Identifier (4 bytes as IPv4) + Optional Parameters Length + walker over " +
		"Optional Parameters. Type 2 Optional Parameters carry Capabilities (RFC " +
		"5492) with **7-entry Capability Code name table**: 1 Multiprotocol " +
		"Extensions (MP-BGP, RFC 4760), 2 Route Refresh (RFC 2918), 64 Graceful " +
		"Restart (RFC 4724), 65 4-byte AS Number (RFC 6793), 67 Dynamic Capability " +
		"(RFC 4396), 70 Enhanced Route Refresh (RFC 7313), 71 Long-Lived Graceful " +
		"Restart (RFC 9494).\n" +
		"- **UPDATE body** (RFC 4271 §4.3): Withdrawn Routes Length + Withdrawn " +
		"Routes (list of length-prefixed prefixes — IPv4 formatted) + Total Path " +
		"Attribute Length + Path Attributes (each with Flags / Type / Length / " +
		"Value) + NLRI (list of length-prefixed prefixes). **13-entry Path Attribute " +
		"Type name table**: ORIGIN, AS_PATH, NEXT_HOP, MULTI_EXIT_DISC, LOCAL_PREF, " +
		"ATOMIC_AGGREGATE, AGGREGATOR, COMMUNITY (RFC 1997), ORIGINATOR_ID, " +
		"CLUSTER_LIST, MP_REACH_NLRI (RFC 4760), MP_UNREACH_NLRI (RFC 4760), " +
		"EXTENDED_COMMUNITIES (RFC 4360), AS4_PATH (RFC 6793), AS4_AGGREGATOR " +
		"(RFC 6793), LARGE_COMMUNITY (RFC 8092).\n" +
		"- **NOTIFICATION body** (RFC 4271 §4.5): Error Code + Error Subcode + Data. " +
		"**6-entry Error Code name table**: Message Header Error, OPEN Message Error, " +
		"UPDATE Message Error, Hold Timer Expired, Finite State Machine Error, Cease " +
		"(RFC 4486). Sub-tables decode Error Subcode per Error Code (e.g. Cease " +
		"subcodes: Admin Shutdown / Peer De-configured / Connection Rejected / etc.).\n" +
		"- **KEEPALIVE body** — empty (always exactly 19 bytes total). Trailing bytes " +
		"surface a non-conformance Note.\n" +
		"- **ROUTE-REFRESH body** (RFC 2918): AFI (uint16 BE) + Reserved (1 byte) + " +
		"SAFI (1 byte). **3-entry AFI name table** (IPv4 / IPv6 / L2VPN); **8-entry " +
		"SAFI name table** (unicast / multicast / MPLS Label / MCAST-VPN / EVPN / " +
		"BGP-LS / VPNv4 / VPNv6).\n\n" +
		"Pure offline parser — operators paste BGP message bytes (TCP port 179 is the " +
		"well-known port; capture a Wireshark Follow-TCP-Stream from a BGP peering " +
		"session, a Quagga / FRR / GoBGP / BIRD debug log, an MRT routing-table dump, " +
		"or any BGP-speaking router's tcpdump) and get the documented header + body " +
		"breakdown.\n\n" +
		"Out of scope (deferred): TCP framing (feed the bytes after TCP/179 stream " +
		"reassembly — BGP messages can span multiple TCP segments); Path Attribute " +
		"deep dissection (AS_PATH segments, COMMUNITY tuples, MP_REACH AFI/SAFI/" +
		"Next-Hop/NLRI parsing — per-attribute body is raw hex; a future Spec would " +
		"walk each type); Capability Value deep dissection beyond code + length + " +
		"raw value; specialised AFI/SAFI types (Route Filter / FlowSpec / RT-" +
		"Constraint); multi-message TCP-stream walking (this Spec handles a single " +
		"BGP message).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational Internet routing " +
		"protocol — runs every ISP backbone). Wrap-vs-native: native — RFC 4271 is " +
		"fully public; wire format is a tight 19-byte fixed header plus per-type " +
		"bit-packed binary bodies; no crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"BGP-4 message bytes (after TCP/179 stream reassembly; one complete message at a time). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   bgpMessageDecodeHandler,
}

func bgpMessageDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("bgp_message_decode: 'hex' is required")
	}
	res, err := bgp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("bgp_message_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
