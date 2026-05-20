// ospfv3.go — host-side OSPFv3 packet decoder Spec.
// Wraps the internal/ospfv3 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ospfv3"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ospfv3DecodeSpec)
}

var ospfv3DecodeSpec = Spec{
	Name: "ospfv3_packet_decode",
	Description: "Decode an OSPFv3 packet per RFC 5340. OSPFv3 is the IPv6 sibling of " +
		"OSPFv2 (RFC 2328, covered by the existing `ospf_packet_decode`); the two " +
		"protocols share the same Hello / DBD / LSR / LSU / LSAck packet-type " +
		"ladder but OSPFv3 uses a slimmer 16-byte common header (drops OSPFv2's " +
		"AuType + 8-byte Auth field — IPv6 expects integrity to come from IP " +
		"AH/ESP) and a richer LS Type encoding split into Flooding Scope (U/S2/S1 " +
		"bits) + 13-bit Function Code. Used in every IPv6-routed network — service-" +
		"provider cores, enterprise IPv6 deployments, dual-stack data centres. " +
		"Pairs with `ospf_packet_decode` for the complete IPv4 + IPv6 OSPF picture. " +
		"Decodes:\n\n" +
		"- **16-byte common header** (RFC 5340 §A.3.1):\n" +
		"  - byte 0: Version (must be 3).\n" +
		"  - byte 1: **Type** with **5-entry name table**: 1 Hello, 2 Database " +
		"Description, 3 Link State Request, 4 Link State Update, 5 Link State " +
		"Acknowledgment.\n" +
		"  - bytes 2-3: Length (uint16 BE).\n" +
		"  - bytes 4-7: Router ID (uint32 BE; canonical dotted-quad).\n" +
		"  - bytes 8-11: Area ID (uint32 BE; dotted-quad).\n" +
		"  - bytes 12-13: Checksum (uint16 BE, hex).\n" +
		"  - byte 14: **Instance ID** (allows multiple OSPFv3 instances per " +
		"interface — RFC 5838 extends this for Address-Family support).\n" +
		"  - byte 15: Reserved.\n" +
		"- **Hello body** (Type 1): Interface ID + Router Priority + 24-bit " +
		"**Options** decoded into **6 named bits** (V6 / E / MC / N / R / DC) + " +
		"HelloInterval + RouterDeadInterval + DR + BDR + zero or more 4-byte " +
		"Neighbor Router IDs.\n" +
		"- **DBD body** (Type 2): Options + Interface MTU + I/M/MS flags + DD " +
		"Sequence Number + zero or more 20-byte LSA Headers.\n" +
		"- **LSR body** (Type 3): array of 12-byte records — LS Type + Link State " +
		"ID + Advertising Router.\n" +
		"- **LSU body** (Type 4): Number of LSAs (uint32 BE) + N LSAs (each " +
		"starting with the 20-byte LSA Header; the body walker uses each LSA's " +
		"Length field to skip to the next).\n" +
		"- **LSAck body** (Type 5): array of 20-byte LSA Headers.\n" +
		"- **20-byte LSA Header** (RFC 5340 §A.4.2) — LS Age + 16-bit LS Type (top " +
		"3 bits = Flooding Scope with 3-entry name table Link-Local / Area / AS; " +
		"low 13 bits = Function Code with **9-entry name table**: Router-LSA / " +
		"Network-LSA / Inter-Area-Prefix-LSA / Inter-Area-Router-LSA / AS-External-" +
		"LSA / Group-Membership-LSA (deprecated MOSPF) / Type-7-LSA (NSSA External) " +
		"/ Link-LSA / Intra-Area-Prefix-LSA) + Link State ID + Advertising Router + " +
		"LS Sequence Number (int32; starts at 0x80000001) + Checksum + Length.\n\n" +
		"Pure offline parser — operators paste OSPFv3 bytes (IP protocol number 89, " +
		"multicast to FF02::5 for AllSPFRouters or FF02::6 for AllDRouters) from a " +
		"`tcpdump -X ip6 proto 89` line or a Wireshark Follow-IPv6-Stream view and " +
		"get the documented header + per-type body breakdown.\n\n" +
		"Out of scope (deferred): IPv6 framing (feed bytes after IPv6 header strip " +
		"— OSPFv3 runs over IP protocol 89); OSPFv2 (use the existing " +
		"`ospf_packet_decode`); per-LSA body parsing (Router-LSA Link records, " +
		"Network-LSA attached routers, Inter-Area-Prefix prefix records, AS-" +
		"External-LSA forwarding address + tag, Link-LSA link-local address + " +
		"prefix options, Intra-Area-Prefix prefix list — LSA Header is decoded " +
		"with Function Code naming + Length, per-Function-Code body walker is a " +
		"separate dissector); OSPFv3 IP-AH/IP-ESP integrity verification " +
		"(deliberately relies on IPv6 security layer for auth); OSPFv3 routing-" +
		"table reasoning (adjacency state machine, SPF run, route summarisation " +
		"— higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational IPv6 IGP routing " +
		"protocol — every IPv6 routed network runs OSPFv3 or IS-IS; natural IPv6 " +
		"sibling to ospf_packet_decode). Wrap-vs-native: native — RFC 5340 is " +
		"fully public; OSPFv3 has a tight 16-byte common header with per-type body " +
		"layouts documented in §A.3 of the RFC; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"OSPFv3 packet bytes (after IPv6 header strip; IP protocol number 89). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ospfv3DecodeHandler,
}

func ospfv3DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ospfv3_packet_decode: 'hex' is required")
	}
	res, err := ospfv3.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ospfv3_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
