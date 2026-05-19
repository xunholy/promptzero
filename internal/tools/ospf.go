// ospf.go — host-side OSPFv2 packet decoder Spec.
// Wraps the internal/ospf walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ospf"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ospfPacketDecodeSpec)
}

var ospfPacketDecodeSpec = Spec{
	Name: "ospf_packet_decode",
	Description: "Decode an OSPFv2 packet per RFC 2328. OSPFv2 is the dominant interior " +
		"gateway protocol (IGP) — every enterprise network, every data-centre, every " +
		"ISP that isn't Cisco-IOS-only EIGRP runs OSPF inside each autonomous system. " +
		"Pairs with `bgp_message_decode` (BGP is the EGP) for the complete inside-" +
		"plus-outside routing picture. Decodes:\n\n" +
		"- **24-byte common header** (RFC 2328 §A.3.1):\n" +
		"  - Version (1 byte; 2 for OSPFv2)\n" +
		"  - **Type** (1 byte) with **5-entry name table**: 1 Hello, 2 Database " +
		"Description (DBD), 3 Link State Request (LSR), 4 Link State Update (LSU), " +
		"5 Link State Acknowledgment (LSAck).\n" +
		"  - Packet Length (uint16 BE)\n" +
		"  - Router ID + Area ID (4 bytes each, IPv4-formatted; Area 0.0.0.0 is the " +
		"backbone)\n" +
		"  - Checksum (uint16 BE, hex-formatted)\n" +
		"  - **AuType** (uint16 BE) with **3-entry name table**: 0 Null, 1 Simple " +
		"Password, 2 Cryptographic Authentication (MD5)\n" +
		"  - Authentication (8 bytes; opaque per AuType)\n" +
		"- **Hello body**: Network Mask + HelloInterval + Options (7-bit name " +
		"breakdown: E/MC/NP/EA/DC/O/DN per RFC 2328 + 4576) + Rtr Pri + " +
		"RouterDeadInterval + Designated Router + Backup Designated Router + list " +
		"of Neighbors (until end of packet).\n" +
		"- **DBD body**: Interface MTU + Options + I/M/MS flags + DD Sequence Number " +
		"+ list of 20-byte LSA Headers.\n" +
		"- **LSR body**: list of 12-byte LSA-request entries (LS Type uint32 BE + " +
		"Link State ID + Advertising Router).\n" +
		"- **LSU body**: Number of LSAs (uint32 BE) + LSAs (each LSA has a 20-byte " +
		"header followed by Length-20 bytes of body, surfaced as raw hex).\n" +
		"- **LSAck body**: list of 20-byte LSA Headers.\n" +
		"- **LSA Header** (20 bytes): LS Age + Options + **LS Type** (9-entry name " +
		"table: Router LSA, Network LSA, Summary LSA network, Summary LSA ASBR, " +
		"AS-External LSA, NSSA External LSA RFC 3101, Link-Local Opaque RFC 5250, " +
		"Area-Local Opaque, AS-wide Opaque) + Link State ID + Advertising Router + " +
		"LS Sequence Number + LS Checksum + Length.\n\n" +
		"Pure offline parser — operators paste OSPF packet bytes (IP protocol number " +
		"89, multicast to 224.0.0.5 / 224.0.0.6) from a `tcpdump -X proto 89` line, " +
		"a Wireshark Follow-IP-Stream view, a Quagga / FRR / BIRD debug log, or any " +
		"OSPF-speaking router's tcpdump and get the documented header + per-type " +
		"body breakdown.\n\n" +
		"Out of scope (deferred): IP framing (feed bytes after IPv4/IPv6 header " +
		"strip — OSPFv2 runs over IP protocol 89); OSPFv3 (RFC 5340 — different " +
		"header layout; future Spec); LSA body deep dissection (Router LSA links, " +
		"Network LSA attached routers, Summary LSA metric/cost, AS-External LSA " +
		"forwarding address are all raw hex past the header — a future Spec walks " +
		"each LS Type); cryptographic verification (AuType 2 MD5 metadata recognised " +
		"but digest verification is a separate Spec); Opaque LSA TLV walking (RFC " +
		"5250 — type 9/10/11 surface the LS Type name but opaque payload is hex).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational interior gateway routing " +
		"protocol — runs every enterprise / data-centre / ISP IGP). Wrap-vs-native: " +
		"native — RFC 2328 is fully public; wire format is a tight 24-byte common " +
		"header plus per-type bit-packed binary bodies; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"OSPFv2 packet bytes (after IPv4/IPv6 header strip; IP protocol number 89). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ospfPacketDecodeHandler,
}

func ospfPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ospf_packet_decode: 'hex' is required")
	}
	res, err := ospf.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ospf_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
