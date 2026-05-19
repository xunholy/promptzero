// arpdecode.go — host-side ARP/RARP packet decoder Spec.
// Wraps the internal/arpdecode walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/arpdecode"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(arpDecodeSpec)
}

var arpDecodeSpec = Spec{
	Name: "arp_decode",
	Description: "Decode an Address Resolution Protocol (ARP) or Reverse ARP (RARP) " +
		"packet per RFC 826 + RFC 903 + the RFC 5227 IPv4 address-conflict-detection " +
		"extensions. ARP is the L2-to-L3 binding protocol every IPv4 network relies on " +
		"— every modern Ethernet network uses ARP to map IP addresses to MAC " +
		"addresses, and every operator deals with ARP cache poisoning / spoofing / " +
		"announcement traffic in practice. Decodes:\n\n" +
		"- **8-byte fixed header**:\n" +
		"  - **Hardware Type** (2 bytes BE) — 10-entry IANA name table (Ethernet / " +
		"IEEE 802 / ARCNET / Frame Relay / ATM / HDLC / Fibre Channel / Serial Line " +
		"/ InfiniBand).\n" +
		"  - **Protocol Type** (2 bytes BE) — the EtherType of the protocol address " +
		"being resolved. 4 documented: 0x0800 IPv4, 0x86DD IPv6, 0x8035 RARP, " +
		"0x809B AppleTalk.\n" +
		"  - **HLEN** (1 byte) — hardware address length, typically 6 for Ethernet.\n" +
		"  - **PLEN** (1 byte) — protocol address length, typically 4 for IPv4 or " +
		"16 for IPv6.\n" +
		"  - **Operation** (2 bytes BE) with **10-entry name table**: 1 Request, 2 " +
		"Reply, 3 RARP Request, 4 RARP Reply, 5 DRARP-Request, 6 DRARP-Reply, 7 " +
		"DRARP-Error, 8 InARP-Request, 9 InARP-Reply, 10 ARP-NAK.\n" +
		"- **4 address fields** (sized via HLEN / PLEN): Sender Hardware Address " +
		"(formatted as MAC for HLEN=6), Sender Protocol Address (formatted as IPv4 " +
		"for PLEN=4, IPv6 for PLEN=16), Target Hardware Address, Target Protocol " +
		"Address.\n" +
		"- **RFC 5227 detection patterns** for IPv4 ARP — surface a Note explaining " +
		"the pattern when one of these is detected:\n" +
		"  - **Gratuitous ARP** — opcode is Request or Reply AND Sender Protocol " +
		"Address == Target Protocol Address. Used for unsolicited cache-update / " +
		"address-takeover announcements.\n" +
		"  - **ARP Probe** (RFC 5227 §1.1) — opcode Request AND Sender Protocol " +
		"Address == 0.0.0.0 AND Target Protocol Address is the address being " +
		"probed. Host sends this before claiming an address to detect conflicts " +
		"(DHCP RFC 5227 mandates ≥1 probe).\n" +
		"  - **ARP Announcement** (RFC 5227 §1.2) — opcode Request AND Sender " +
		"Protocol Address == Target Protocol Address (the canonical post-probe " +
		"announcement that the host has claimed the address).\n\n" +
		"Pure offline parser — operators paste ARP-payload bytes (after the Ethernet " +
		"header strip; EtherType 0x0806 for ARP, 0x8035 for RARP) from a " +
		"`tcpdump -i ethX -X ether proto arp` line, a Wireshark Follow-Frame view, " +
		"an `arping` capture, or any ARP-emitting tool and inspect every documented " +
		"field. Defensive primitive — operators use this to spot ARP cache poisoning " +
		"(unexpected gratuitous announcements), DHCP-class duplicate-address detection " +
		"(ARP probes), and address-takeover events (gratuitous replies for an IP " +
		"already in cache).\n\n" +
		"Out of scope (deferred): Ethernet framing (feed the ARP payload after the " +
		"dst MAC + src MAC + EtherType bytes); Neighbor Discovery Protocol (IPv6's " +
		"ARP replacement — already in `icmp_packet_decode` as NDP Neighbor Sol/Adv " +
		"/ Redirect); 802.1Q VLAN tag stripping (feed the post-tag ARP payload); " +
		"ARP table state (we decode individual packets; ARP cache reconstruction " +
		"belongs in a session-tracker).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational L2-to-L3 binding " +
		"protocol). Wrap-vs-native: native — RFC 826 is one of the oldest standards-" +
		"track RFCs (1982); wire format is a tight 8-byte fixed header followed by " +
		"4 length-parameterised address fields. No crypto, no compression, no varints.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"ARP/RARP packet bytes (after the Ethernet header) as hex. Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   arpDecodeHandler,
}

func arpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("arp_decode: 'hex' is required")
	}
	res, err := arpdecode.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("arp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
