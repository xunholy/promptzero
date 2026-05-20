// natpmp.go — host-side NAT-PMP message decoder Spec.
// Wraps the internal/natpmp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/natpmp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(natpmpDecodeSpec)
}

var natpmpDecodeSpec = Spec{
	Name: "natpmp_decode",
	Description: "Decode a NAT-PMP (NAT Port Mapping Protocol) message per RFC 6886. " +
		"NAT-PMP is the predecessor to PCP (RFC 6887, covered by `pcp_decode`) — " +
		"Apple's 2008 design that PCP superseded in 2013 but which remains widely " +
		"deployed in older residential broadband CPE (every Apple Airport / Time " +
		"Capsule / early Asus / Belkin / Linksys router shipped before ~2014 " +
		"speaks NAT-PMP rather than PCP). Modern peer-to-peer applications " +
		"(BitTorrent clients, Tailscale, libnatpmp) try NAT-PMP first and fall " +
		"back to UPnP IGD when neither NAT-PMP nor PCP works. Decodes:\n\n" +
		"- **Common header**: byte 0 = Version (must be 0 for NAT-PMP; version 2 " +
		"indicates PCP — use `pcp_decode` instead, surfaced as a Note); byte 1 = " +
		"**Opcode** with the high bit signalling direction (Request when clear, " +
		"Response when set). **6-entry opcode name table**: 0 Public Address " +
		"Request / 1 Map UDP Request / 2 Map TCP Request / 128 Public Address " +
		"Response / 129 Map UDP Response / 130 Map TCP Response.\n" +
		"- **Public Address Request** (Opcode 0, 2 bytes total) — Version + " +
		"Opcode only; client asks the gateway for its WAN-facing IP.\n" +
		"- **Public Address Response** (Opcode 128, 12 bytes) — adds 2-byte " +
		"Result Code + 4-byte Seconds Since Epoch (server-anchor counter for " +
		"mapping-validity comparisons) + 4-byte Public IP (IPv4 — NAT-PMP is " +
		"IPv4-only; IPv6 hosts use PCP).\n" +
		"- **Map Request** (Opcode 1 UDP / 2 TCP, 12 bytes) — 2-byte Reserved + " +
		"2-byte Internal Port + 2-byte Suggested External Port (client hint) + " +
		"4-byte Requested Lifetime (seconds; 0 = delete mapping).\n" +
		"- **Map Response** (Opcode 129 UDP / 130 TCP, 16 bytes) — 2-byte Result " +
		"Code + 4-byte Seconds Since Epoch + 2-byte Internal Port + 2-byte " +
		"Mapped External Port (granted; may differ from suggestion) + 4-byte " +
		"Granted Lifetime.\n" +
		"- **6-entry Result Code name table** (RFC 6886 §3.5): 0 SUCCESS / 1 " +
		"UNSUPP_VERSION / 2 NOT_AUTHORIZED (gateway refused; common when the " +
		"gateway administratively disables NAT-PMP) / 3 NETWORK_FAILURE (no " +
		"upstream connectivity) / 4 OUT_OF_RESOURCES (port range exhausted; " +
		"client should retry later) / 5 UNSUPPORTED_OPCODE.\n\n" +
		"Pure offline parser — operators paste NAT-PMP bytes (UDP destination " +
		"port 5351 server-side; clients listen on UDP 5350 for unsolicited " +
		"Public Address change announcements) from a `tcpdump -X udp port 5351` " +
		"line or a Wireshark Follow-UDP-Stream view.\n\n" +
		"Out of scope (deferred): UDP framing (feed NAT-PMP bytes after the UDP " +
		"header strip — NAT-PMP runs on UDP destination port 5351; clients " +
		"listen on UDP 5350 for unsolicited Public Address change " +
		"announcements); PCP (RFC 6887 — successor protocol with IPv6 + peer-" +
		"mapping + TLV options; use `pcp_decode`); UPnP IGD (different protocol " +
		"family — HTTP/XML over SSDP discovery; not related to NAT-PMP); NAT-PMP " +
		"unsolicited announcements (Version=0 Opcode=128 sent to clients on UDP " +
		"5350 when the gateway WAN IP changes; decoded with the standard Public " +
		"Address Response layout — the operator's framing context tells them " +
		"whether it's a unicast reply or a multicast announcement).\n\n" +
		"Source: docs/catalog/gap-analysis.md (foundational NAT/firewall " +
		"configuration protocol; predecessor to PCP; still widely deployed in " +
		"older residential broadband CPE; consumed by every modern peer-to-peer " +
		"application that needs inbound connectivity). Wrap-vs-native: native — " +
		"RFC 6886 is fully public; NAT-PMP has tight fixed-position 2/12/16-" +
		"byte messages with no crypto, no variable-length fields.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"NAT-PMP message bytes (after UDP header strip; UDP destination port 5351 server-side or 5350 client-side for announcements). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   natpmpDecodeHandler,
}

func natpmpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("natpmp_decode: 'hex' is required")
	}
	res, err := natpmp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("natpmp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
