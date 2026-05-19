// dhcp.go — host-side DHCPv4 packet dissector Spec,
// delegating to the internal/dhcp package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dhcp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dhcpPacketDecodeSpec)
}

var dhcpPacketDecodeSpec = Spec{
	Name: "dhcp_packet_decode",
	Description: "Decode a DHCPv4 packet — the second most-captured wired-network protocol " +
		"after DNS, used by every laptop / phone / IoT device that joins a network. Per " +
		"RFC 2131 (envelope) + RFC 2132 (options) + supporting RFCs. Companion to " +
		"dns_packet_decode for the core network-bootstrap decode stack. Decodes:\n\n" +
		"- **BOOTP envelope** (RFC 951 + RFC 2131 §2): op (BOOTREQUEST / BOOTREPLY), htype " +
		"+ hlen (Ethernet supported with MAC addresses rendered as colon-hex), hops, xid " +
		"(transaction ID), secs, flags (broadcast bit), ciaddr / yiaddr / siaddr / giaddr " +
		"in dotted-decimal, chaddr (first hlen bytes as MAC), null-trimmed sname + file " +
		"fields.\n" +
		"- **Magic cookie validation**: the 4-byte 0x63825363 at offset 236 must be present " +
		"to distinguish DHCP from vanilla BOOTP (which uses the same envelope but no " +
		"options).\n" +
		"- **DHCP options walker** with type-specific decode for the operationally-" +
		"important options:\n" +
		"  - **53 DHCP Message Type** (DISCOVER / OFFER / REQUEST / DECLINE / ACK / NAK / " +
		"RELEASE / INFORM / FORCERENEW + LEASEQUERY family).\n" +
		"  - **1 Subnet Mask** / **3 Router** / **6 DNS Server** / **42 NTP Servers** / " +
		"**44 NetBIOS Name Server** / **45 NetBIOS DDS** — single IPv4 or list.\n" +
		"  - **12 Host Name** / **15 Domain Name** / **17 Root Path** / **40 NIS Domain** " +
		"/ **60 Vendor Class Identifier** / **61 Client Identifier** / **66 TFTP Server " +
		"Name** / **67 Boot File Name** / **77 User Class** — ASCII strings.\n" +
		"  - **28 Broadcast Address** / **50 Requested IP** / **54 DHCP Server " +
		"Identifier** — single IPv4.\n" +
		"  - **51 IP Address Lease Time** / **57 Maximum DHCP Message Size** / **58 " +
		"Renewal Time** / **59 Rebinding Time** — uint32 seconds / bytes.\n" +
		"  - **55 Parameter Request List** — list of option codes the client is asking " +
		"the server to include, rendered with full option-name lookup so operators see " +
		"`['Subnet Mask', 'Router', 'DNS Server', 'Domain Name', ...]` rather than raw " +
		"integers.\n" +
		"  - **81 Client FQDN** (RFC 4702) — flags + A-record result + AAAA-record " +
		"result + FQDN.\n" +
		"  - **82 Relay Agent Information** (RFC 3046) — with sub-option walk (Agent " +
		"Circuit ID, Agent Remote ID, DOCSIS Device Class, Link Selection, Subscriber " +
		"ID, RADIUS Attributes, Vendor-Specific Information, etc.).\n" +
		"  - **119 Domain Search** (RFC 3397) — DNS-compressed list of search-domain " +
		"FQDNs.\n" +
		"  - **121 Classless Static Route** (RFC 3442) — list of (destination, prefix-" +
		"length, gateway) tuples with compressed destination encoding.\n" +
		"- ~50-entry option name lookup table covering every option from RFC 2132 + " +
		"RFC 3046 + RFC 3203 + RFC 3397 + RFC 4361 + RFC 4702 + RFC 5970 + RFC 7291 " +
		"+ RFC 7710 + RFC 8043 + IANA dhcpv4-parameters registry.\n" +
		"- Every option that isn't deep-decoded above is still surfaced with code + " +
		"name + length + raw hex.\n\n" +
		"Pure offline parser — operators paste a hex blob from Wireshark / tshark / " +
		"tcpdump-of-67/68 / `dhcpdump` / `dnsmasq --log-dhcp` / similar tooling and " +
		"inspect every documented field without re-attaching to the network. " +
		"Complements dns_packet_decode for the core network-bootstrap decode stack: " +
		"DHCP for IP-address assignment + nameserver discovery, DNS for name-to-IP " +
		"resolution.\n\n" +
		"Out of scope (deferred to future iterations): DHCPv6 (RFC 8415) — entirely " +
		"different envelope; DHCP authentication (option 90, RFC 3118) — niche; " +
		"PXE / boot-time vendor-specific options — surfaced as raw hex; encapsulated " +
		"relay forms — operators feed the inner DHCP message after stripping outer " +
		"transport.\n\n" +
		"Source: docs/catalog/gap-analysis.md (core network-bootstrap decode space — " +
		"companion to dns_packet_decode). Wrap-vs-native: native — RFC 2131 + 2132 " +
		"are fully public, wire format is fixed-format BOOTP header + variable-length " +
		"options TLV, dispatch is a switch.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators and a leading '0x' prefix.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded DHCPv4 packet: 236-byte BOOTP header + 4-byte magic cookie (0x63825363) + variable-length options TLV list terminated by option 255. Minimum 240 bytes. ':' / '-' / '_' / whitespace separators tolerated; '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dhcpPacketDecodeHandler,
}

func dhcpPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("dhcp_packet_decode: 'hex' is required")
	}
	res, err := dhcp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("dhcp_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
