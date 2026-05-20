// ndp.go — host-side ICMPv6 NDP (Neighbor Discovery Protocol)
// decoder Spec. Wraps the internal/ndp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ndp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ndpDecodeSpec)
}

var ndpDecodeSpec = Spec{
	Name: "ndp_decode",
	Description: "Decode an ICMPv6 NDP (Neighbor Discovery Protocol) message per RFC " +
		"4861 (base NDP) + RFC 4191 (Default Router Preferences + Route " +
		"Information) + RFC 8106 (RDNSS / DNSSL for SLAAC-only IPv6 hosts). " +
		"NDP is the foundational signalling layer of IPv6 — every IPv6 host " +
		"speaks NDP for neighbor resolution (the IPv6 equivalent of ARP), " +
		"router discovery, parameter discovery, redirect handling, and " +
		"duplicate-address detection. Operationally interesting because NDP " +
		"carries every step of how a fresh IPv6 host learns its environment: " +
		"Router Solicitation 'any routers out there?' to FF02::2; Router " +
		"Advertisement (the canonical mitm6 / suddensix / fake_router6 attack " +
		"target carrying SLAAC prefix + DNS servers + default-route lifetime); " +
		"Neighbor Solicitation 'who has this IPv6?' (the IPv6 ARP); Neighbor " +
		"Advertisement with O=Override flag (the IPv6 gratuitous ARP — " +
		"abusable for ND-cache poisoning); Redirect (historically abusable for " +
		"IPv6 redirect attacks). The NDP Options TLV stream carries the actual " +
		"interesting data: Source/Target Link-Layer Addresses (the IPv6→MAC " +
		"binding), Prefix Information (SLAAC prefix + on-link bit + autoconfig " +
		"bit + lifetime), MTU, RDNSS (the DNS servers the host should use — " +
		"leak target for mitm6 + rogue RA attacks), DNSSL (DNS search domain " +
		"list). Decodes:\n\n" +
		"- **ICMPv6 header** (RFC 4443 §2, 4 bytes, big-endian): Type + Code " +
		"(always 0 for NDP) + Checksum.\n" +
		"- **5-entry NDP type name table** (RFC 4861 §4): 133 " +
		"Router_Solicitation / 134 Router_Advertisement / 135 " +
		"Neighbor_Solicitation / 136 Neighbor_Advertisement / 137 Redirect.\n" +
		"- **Router Advertisement body** (RFC 4861 §4.2, 12 bytes): CurHopLimit " +
		"+ Flags (M=Managed Address Configuration / O=Other Configuration / " +
		"H=Home Agent / Prf=Default Router Preference per RFC 4191 — " +
		"Medium/High/Reserved/Low / P=Proxy) + Router Lifetime + Reachable " +
		"Time + Retrans Timer.\n" +
		"- **Neighbor Solicitation body** (RFC 4861 §4.3, 20 bytes): Target " +
		"Address (IPv6).\n" +
		"- **Neighbor Advertisement body** (RFC 4861 §4.4, 20 bytes): Flags " +
		"(R=Router / S=Solicited / O=Override) + Target Address.\n" +
		"- **Redirect body** (RFC 4861 §4.5, 36 bytes): Target Address (better " +
		"next-hop) + Destination Address (original destination).\n" +
		"- **NDP Options TLV walker** (RFC 4861 §4.6): each option is byte 0 " +
		"Type + byte 1 Length-in-8-byte-units + payload.\n" +
		"- **9-entry NDP Option type name table**: 1 Source_Link_Layer_Address / " +
		"2 Target_Link_Layer_Address / 3 Prefix_Information / 4 " +
		"Redirected_Header / 5 MTU / 13 Nonce (RFC 3971 SeND) / 24 " +
		"Route_Information (RFC 4191) / 25 RDNSS (RFC 8106 Recursive DNS " +
		"Server) / 31 DNSSL (RFC 8106 DNS Search List).\n" +
		"- **Per-option decoders**: SLLA/TLLA → 6-byte MAC; Prefix Information " +
		"→ PrefixLength + L/A/R flags + Valid + Preferred lifetimes + IPv6 " +
		"prefix; MTU → 32-bit MTU override; RDNSS → lifetime + IPv6 DNS-server " +
		"list (the leak target for mitm6 + rogue RA attacks); DNSSL → lifetime " +
		"+ DNS search-domain list (length-prefixed labels with 0x00 root " +
		"terminator per RFC 1035 §3.1); Route Information → PrefixLength + " +
		"Preference + Route Lifetime + Prefix.\n\n" +
		"Pure offline parser — operators paste NDP bytes (starting at the " +
		"ICMPv6 Type byte; after the IPv6 header strip — Next Header = 58) " +
		"from a `tcpdump -X icmp6` line or a Wireshark ICMPv6/NDP dissector " +
		"view and get the documented per-type body + Options TLV breakdown.\n\n" +
		"Out of scope (deferred): IPv6 framing (feed bytes after the IPv6 " +
		"header strip; standard L3 destination is FF02::1 all-nodes / FF02::2 " +
		"all-routers / FF02::1:FFxx:xxxx solicited-node); non-NDP ICMPv6 " +
		"messages (Types 1-4 errors, 128/129 Echo, 130-132 MLD, 143 MLDv2 — " +
		"covered by the existing icmp_packet_decode Spec or out of scope); " +
		"checksum verification (ICMPv6 checksum computed over IPv6 pseudo-" +
		"header + ICMPv6 message — out of scope unless we have the L3 pseudo-" +
		"header); SeND Secure Neighbor Discovery (RFC 3971 CGA + RSA Signature " +
		"options — Nonce option name surfaces but CGA + RSA Signature options " +
		"are not decoded); DAD Duplicate Address Detection state-machine " +
		"reasoning (per-address tentative / preferred / deprecated / invalid " +
		"state machine — higher-level analysis).\n\n" +
		"Source: docs/catalog/gap-analysis.md (IPv6 reconnaissance + mitm6 " +
		"pentest dissector — pairs with the existing dhcpv6_decode for full " +
		"IPv6 address-acquisition coverage; targets DEF CON Recon Village + " +
		"IPv6 pentest engagements; canonical decode for SLAAC poisoning + RA-" +
		"guard bypass research). Wrap-vs-native: native — RFC 4861 + 4191 + " +
		"8106 are publicly available; NDP uses a tight 4-byte ICMPv6 header + " +
		"per-type fixed fields + a TLV Options stream; no crypto at the parse " +
		"layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"ICMPv6 NDP message bytes starting at the ICMPv6 Type byte (after the IPv6 header strip; Next Header = 58). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ndpDecodeHandler,
}

func ndpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ndp_decode: 'hex' is required")
	}
	res, err := ndp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ndp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
