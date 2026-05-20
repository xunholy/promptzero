// dhcpv6.go — host-side DHCPv6 packet decoder Spec.
// Wraps the internal/dhcpv6 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dhcpv6"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dhcpv6DecodeSpec)
}

var dhcpv6DecodeSpec = Spec{
	Name: "dhcpv6_decode",
	Description: "Decode a DHCPv6 packet per RFC 8415 (which consolidates RFC 3315 + " +
		"RFC 3633 prefix delegation + RFC 3646 DNS configuration + RFC 4242 info " +
		"refresh time + RFC 7083 rapid-commit / unicast updates into one current " +
		"spec). DHCPv6 is the stateful IPv6 address-assignment + configuration " +
		"protocol used alongside SLAAC on every dual-stack network; every consumer " +
		"IPv6 router (M-bit set in RA), every cellular IPv6 carrier, every " +
		"enterprise IPv6 deployment runs DHCPv6 for at least DNS / NTP / Prefix " +
		"Delegation. IPv6 sibling to the existing `dhcp_packet_decode`. Decodes:\n\n" +
		"- **4-byte fixed header** (RFC 8415 §8): byte 0 = **Message Type** with " +
		"**13-entry name table** (SOLICIT / ADVERTISE / REQUEST / CONFIRM / RENEW " +
		"/ REBIND / REPLY / RELEASE / DECLINE / RECONFIGURE / INFORMATION-REQUEST " +
		"/ RELAY-FORW / RELAY-REPL); bytes 1-3 = **Transaction ID** (24-bit BE).\n" +
		"- **Relay-Forward / Relay-Reply 34-byte header** (msg types 12 + 13, " +
		"RFC 8415 §9): Hop Count + 16-byte Link-Address + 16-byte Peer-Address + " +
		"options (typically OPTION_RELAY_MSG carrying the encapsulated packet).\n" +
		"- **TLV option walker** — repeated (Code uint16 BE, Length uint16 BE, " +
		"Value) records. **~25-entry option code name table** covering RFC 8415 " +
		"§21 + IANA DHCPv6 Options registry: OPTION_CLIENTID (1) / OPTION_SERVERID " +
		"(2) / OPTION_IA_NA (3) / OPTION_IA_TA (4) / OPTION_IAADDR (5) / " +
		"OPTION_ORO (6) / OPTION_PREFERENCE (7) / OPTION_ELAPSED_TIME (8) / " +
		"OPTION_RELAY_MSG (9) / OPTION_AUTH (11) / OPTION_UNICAST (12) / " +
		"OPTION_STATUS_CODE (13) / OPTION_RAPID_COMMIT (14) / OPTION_USER_CLASS " +
		"(15) / OPTION_VENDOR_CLASS (16) / OPTION_VENDOR_OPTS (17) / " +
		"OPTION_INTERFACE_ID (18) / OPTION_RECONF_MSG (19) / OPTION_RECONF_ACCEPT " +
		"(20) / OPTION_DNS_SERVERS (23) / OPTION_DOMAIN_LIST (24) / OPTION_IA_PD " +
		"(25) / OPTION_IAPREFIX (26) / OPTION_CLIENT_FQDN (39) / OPTION_NTP_SERVER " +
		"(56).\n" +
		"- **DUID parsing** (RFC 8415 §11) — inside ClientID + ServerID: uint16 BE " +
		"DUID Type with **4-entry table**: 1 DUID-LLT (Hardware type + Time since " +
		"2000-01-01 UTC surfaced as RFC 3339 + Link-Layer Address), 2 DUID-EN " +
		"(Enterprise Number + opaque identifier), 3 DUID-LL (Hardware type + " +
		"Link-Layer Address), 4 DUID-UUID (16-byte UUID).\n" +
		"- **IA_NA / IA_PD body** — first 12 bytes are IAID + T1 + T2 (uint32 BE " +
		"each); remainder is a nested TLV list (typically IAADDR for IA_NA or " +
		"IAPREFIX for IA_PD).\n" +
		"- **IAADDR body** — 16-byte IPv6 + Preferred Lifetime + Valid Lifetime + " +
		"nested options.\n" +
		"- **IAPREFIX body** — Preferred Lifetime + Valid Lifetime + Prefix Length " +
		"+ 16-byte IPv6 Prefix + nested options.\n" +
		"- **Status Code body** — uint16 BE status code with **7-entry name " +
		"table** (Success / UnspecFail / NoAddrsAvail / NoBinding / NotOnLink / " +
		"UseMulticast / NoPrefixAvail) + UTF-8 message string.\n\n" +
		"Pure offline parser — operators paste DHCPv6 bytes (UDP destination port " +
		"547 server-side / 546 client-side, multicast to FF02::1:2 for the " +
		"all-DHCP-relay-agents-and-servers address) from a `tcpdump -X 'udp port " +
		"547'` line or a Wireshark Follow-UDP-Stream view and get the documented " +
		"header + per-option breakdown.\n\n" +
		"Out of scope (deferred): UDP / IPv6 framing (feed bytes after the UDP " +
		"header strip — DHCPv6 ships on UDP, destination port 547 server-side / " +
		"546 client-side); DHCPv4 (that's the existing `dhcp_packet_decode` Spec; " +
		"this Spec handles only v6); OPTION_AUTH integrity verification (RFC 8415 " +
		"§21.11 surfaces the auth payload as hex; verifying the digest would " +
		"require the receiver to know the shared key); DHCPv6 multi-message state " +
		"machine reasoning (higher-level); RFC 1035 label-pointer decompression " +
		"inside OPTION_DOMAIN_LIST (would duplicate dns_packet_decode logic).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational IPv6 configuration " +
		"protocol — every dual-stack network runs DHCPv6 alongside SLAAC; natural " +
		"IPv6 sibling to dhcp_packet_decode). Wrap-vs-native: native — RFC 8415 " +
		"is fully public; DHCPv6 has a tight 4-byte fixed header (or 34-byte for " +
		"Relay messages) followed by a uniform TLV option list; no crypto, no " +
		"compression.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"DHCPv6 packet bytes (after UDP header strip; UDP destination port 547 server-side / 546 client-side). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dhcpv6DecodeHandler,
}

func dhcpv6DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dhcpv6_decode: 'hex' is required")
	}
	res, err := dhcpv6.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dhcpv6_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
