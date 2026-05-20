// pcp.go — host-side PCP message decoder Spec.
// Wraps the internal/pcp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/pcp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(pcpDecodeSpec)
}

var pcpDecodeSpec = Spec{
	Name: "pcp_decode",
	Description: "Decode a PCP (Port Control Protocol) message per RFC 6887. PCP is the " +
		"modern NAT/firewall configuration protocol that supersedes NAT-PMP (RFC " +
		"6886) and adds IPv6 support, peer-mapping (for hole-punching), and a " +
		"more flexible TLV-options envelope. Universal in residential broadband " +
		"CPE (every ASUS / Netgear / Fritz!Box router / CGNAT enforcement at " +
		"carriers since ~2014); used directly by uTorrent / qBittorrent / " +
		"Tailscale's libpcp / libnatpmp / miniupnpd to request external port " +
		"mappings on behalf of inbound-listening applications. Decodes:\n\n" +
		"- **24-byte common header** (RFC 6887 §7.1): Version (must be 2) + R-bit " +
		"(0 Request / 1 Response) + low-7-bit **Opcode** with **3-entry name " +
		"table**: 0 ANNOUNCE / 1 MAP / 2 PEER.\n" +
		"- **Request headers** (R=0): Reserved + Requested Lifetime + 16-byte " +
		"PCP Client IP Address (IPv4-mapped or IPv6).\n" +
		"- **Response headers** (R=1): Reserved + **Result Code** with **14-entry " +
		"name table** (0 SUCCESS / 1 UNSUPP_VERSION / 2 NOT_AUTHORIZED / 3 " +
		"MALFORMED_REQUEST / 4 UNSUPP_OPCODE / 5 UNSUPP_OPTION / 6 " +
		"MALFORMED_OPTION / 7 NETWORK_FAILURE / 8 NO_RESOURCES / 9 " +
		"UNSUPP_PROTOCOL / 10 USER_EX_QUOTA / 11 CANNOT_PROVIDE_EXTERNAL / 12 " +
		"ADDRESS_MISMATCH / 13 EXCESSIVE_REMOTE_PEERS) + Lifetime (granted; or " +
		"error retry-after) + Epoch Time (server's monotonic re-anchor counter) " +
		"+ Reserved.\n" +
		"- **MAP opcode body** (Opcode 1; RFC 6887 §11): Mapping Nonce (12-byte " +
		"client cookie) + Protocol (with **10-entry IP-protocol name table** — " +
		"ICMP / TCP / UDP / DCCP / GRE / ESP / AH / ICMPv6 / SCTP) + Internal " +
		"Port + Suggested External Port + Suggested External IP Address.\n" +
		"- **PEER opcode body** (Opcode 2; RFC 6887 §12) — same as MAP plus " +
		"Remote Peer Port + Remote Peer IP Address.\n" +
		"- **ANNOUNCE opcode** (Opcode 0) — no opcode-specific body; signals " +
		"server epoch reset (clients must refresh all mappings when received).\n" +
		"- **Options walker** (RFC 6887 §7.3) — optional TLV records appended " +
		"after the opcode body. Each option: 1-byte Code (high bit = mandatory) " +
		"+ 1-byte Reserved + 2-byte Length + Value (padded to 4-byte boundary). " +
		"**5-entry option code name table**: 1 THIRD_PARTY (RFC 6887; request " +
		"mapping on behalf of another IP) / 2 PREFER_FAILURE (don't downgrade to " +
		"a different port if requested unavailable) / 3 FILTER (restrict the " +
		"mapping to a specific peer) / 4 NAT64_PREFIX (RFC 7225; DS-Lite/NAT64 " +
		"prefix discovery) / 5 PORT_SET (RFC 7753; request multiple consecutive " +
		"ports as one mapping).\n\n" +
		"Pure offline parser — operators paste PCP bytes (UDP destination port " +
		"5351 server-side; clients listen on UDP 5350 for ANNOUNCE multicasts) " +
		"from a `tcpdump -X udp port 5351` line or a Wireshark Follow-UDP-Stream " +
		"view and get the documented header + opcode-body + options breakdown.\n\n" +
		"Out of scope (deferred): UDP framing (feed PCP bytes after UDP header " +
		"strip — PCP runs on UDP destination port 5351 server-side, UDP 5350 " +
		"client-side for ANNOUNCE multicasts); NAT-PMP (RFC 6886 — the " +
		"predecessor protocol; 8-byte messages, IPv4-only; could share most " +
		"decoder logic but has a different envelope; deferred); PCP " +
		"Authentication (RFC 7652 — optional auth extension via 2 additional " +
		"option types; surfaced as raw hex via the generic option walker).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational NAT/firewall " +
		"configuration protocol; universal in residential broadband CPE + CGNAT " +
		"enforcement at carriers since ~2014; consumed by every modern peer-to-" +
		"peer application that needs inbound connectivity). Wrap-vs-native: " +
		"native — RFC 6887 is fully public; PCP has a tight 24-byte common " +
		"header with R-bit dispatch + opcode-specific body + optional TLV " +
		"options walker; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"PCP message bytes (after UDP header strip; UDP destination port 5351 server-side or 5350 client-side). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   pcpDecodeHandler,
}

func pcpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("pcp_decode: 'hex' is required")
	}
	res, err := pcp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("pcp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
