// igmp.go — host-side IGMP packet decoder Spec.
// Wraps the internal/igmp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/igmp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(igmpDecodeSpec)
}

var igmpDecodeSpec = Spec{
	Name: "igmp_decode",
	Description: "Decode an Internet Group Management Protocol (IGMP) packet per RFC " +
		"3376 (IGMPv3) and RFC 2236 (IGMPv2). IGMPv1 (RFC 1112) is recognised as a " +
		"degenerate v2 form. IGMP is the IPv4 multicast group-management protocol — " +
		"every multicast-aware switch + router runs it and every IPv4 multicast app " +
		"(IPTV, MDNS, OSPF, video conferencing, streaming, market-data feeds) emits " +
		"or consumes it. Pairs with `icmp_packet_decode` (which already covers MLDv1/v2 " +
		"as ICMPv6 type 130-132 + 143) for the complete IPv4 + IPv6 multicast " +
		"signalling picture. Decodes:\n\n" +
		"- **Version auto-detection** — Type 0x11 with body length 8 = IGMPv1/v2 " +
		"General Query; Type 0x11 with body length ≥ 12 = IGMPv3 Membership Query; " +
		"Type 0x22 = IGMPv3 Membership Report; Type 0x16 = IGMPv2 Membership Report; " +
		"Type 0x17 = IGMPv2 Leave Group; Type 0x12 = IGMPv1 Membership Report (legacy).\n" +
		"- **IGMPv2 fixed 8-byte header** (RFC 2236 §2):\n" +
		"  - byte 0: **Type** with **5-entry name table**: 0x11 Membership Query, " +
		"0x12 IGMPv1 Membership Report, 0x16 IGMPv2 Membership Report, 0x17 Leave " +
		"Group, 0x22 IGMPv3 Membership Report (dispatched separately).\n" +
		"  - byte 1: Max Resp Time (1/10 seconds for v2; encoded Max Resp Code for " +
		"v3 Query — exp+mantissa per RFC 3376 §4.1.1, surfaced both as the encoded " +
		"byte and the decoded centiseconds + milliseconds).\n" +
		"  - bytes 2-3: Checksum (uint16 BE, hex-formatted).\n" +
		"  - bytes 4-7: Group Address (4 bytes IPv4; 0.0.0.0 for General Query).\n" +
		"- **IGMPv3 Query body extension** (RFC 3376 §4.1):\n" +
		"  - byte 8: 4-bit Resv + 1-bit **S** (Suppress Router-Side processing flag) " +
		"+ 3-bit **QRV** (Querier's Robustness Variable; default 2).\n" +
		"  - byte 9: **QQIC** (Querier's Query Interval Code — same exp+mantissa " +
		"encoding as Max Resp Code).\n" +
		"  - bytes 10-11: Number of Sources (uint16 BE) + N × 4-byte Source " +
		"Addresses.\n" +
		"- **IGMPv3 Membership Report body** (RFC 3376 §4.2):\n" +
		"  - bytes 4-5: Reserved + bytes 6-7: Number of Group Records + Group Records " +
		"(variable; each is 8-byte fixed header + N source addresses + Aux Data):\n" +
		"    - byte 0: **Record Type** with **6-entry name table**: 1 " +
		"MODE_IS_INCLUDE, 2 MODE_IS_EXCLUDE, 3 CHANGE_TO_INCLUDE_MODE, 4 " +
		"CHANGE_TO_EXCLUDE_MODE, 5 ALLOW_NEW_SOURCES, 6 BLOCK_OLD_SOURCES.\n" +
		"    - byte 1: Aux Data Len (in 4-byte words; should be 0 per RFC 3376).\n" +
		"    - bytes 2-3: Number of Sources (uint16 BE) + bytes 4-7: Multicast " +
		"Address (IPv4) + N × 4-byte Source Addresses + Aux Data Len × 4-byte " +
		"Auxiliary Data (deprecated; surfaced as raw hex).\n\n" +
		"Pure offline parser — operators paste IGMP bytes (IP protocol number 2, " +
		"multicast to 224.0.0.1 for General Queries or 224.0.0.22 for IGMPv3 Reports) " +
		"from a `tcpdump -X proto 2` line, a Wireshark Follow-IP-Stream view, or any " +
		"IGMP-speaking router's tcpdump and get the documented header + per-version " +
		"body breakdown.\n\n" +
		"Out of scope (deferred): IP framing (feed bytes after IPv4 header strip — " +
		"IGMP runs over IP protocol 2); MLD (Multicast Listener Discovery, RFC 3810 " +
		"— IPv6 equivalent; partially decoded by `icmp_packet_decode`); IGMP " +
		"Router-Side state machine (Query intervals, Robustness Variable retries, " +
		"group-membership timeouts — that's higher-level analysis); IP Router Alert " +
		"option (RFC 2113 — checked at the IP layer, not in IGMP).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational IPv4 multicast group-" +
		"management protocol — universal in switched + routed multicast networks). " +
		"Wrap-vs-native: native — RFC 2236 + RFC 3376 are fully public; wire format " +
		"is a tight 8-byte fixed header (v2) or 12+-byte header (v3 Query) with a " +
		"per-record list (v3 Report); no crypto, no compression, no varints apart " +
		"from the exp+mantissa Max Resp Code encoding.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"IGMP packet bytes (after IPv4 header strip; IP protocol number 2). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   igmpDecodeHandler,
}

func igmpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("igmp_decode: 'hex' is required")
	}
	res, err := igmp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("igmp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
