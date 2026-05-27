// isis.go — host-side IS-IS wire-protocol decoder Spec.
// Wraps the internal/isis walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/isis"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(isisDecodeSpec)
}

var isisDecodeSpec = Spec{
	Name: "isis_decode",
	Description: "Decode an IS-IS (Intermediate System to Intermediate System) " +
		"PDU per ISO 10589 and RFC 1195. IS-IS runs directly over L2 (OSI " +
		"CLNS) — it has no IP header. On Ethernet it uses LLC/SNAP " +
		"encapsulation; on point-to-point links it rides HDLC or PPP.\n\n" +
		"IS-IS is the **backbone IGP for large ISP and enterprise networks** " +
		"and is a high-value routing target. Unlike IP-based routing protocols " +
		"it runs at L2, making it accessible to any device on the same segment. " +
		"Default IS-IS has NO authentication — any L2-adjacent device can inject " +
		"LSPs, redirect all traffic through an attacker (MITM at ISP scale), " +
		"or black-hole arbitrary prefixes. IS-IS has been targeted in several " +
		"real-world ISP attacks.\n\n" +
		"The wire format leaks: **system IDs + area addresses** — every Hello " +
		"and LSP encodes the complete L2 topology; area addresses reveal the " +
		"IS-IS area structure; system IDs identify every router; together they " +
		"enable offline topology reconstruction; **dynamic hostname (TLV 137)** " +
		"— maps system IDs to human-readable router names (e.g., " +
		"'core-router-nyc-01'), directly disclosing network topology and naming " +
		"conventions; **authentication (TLV 10)** — absent TLV 10 means NO " +
		"AUTHENTICATION; cleartext password (auth_type 1) transmits the password " +
		"in plain text; HMAC-MD5 (auth_type 54) is offline-crackable via " +
		"hashcat; **IP interface addresses (TLV 132)** — every IS-IS Hello " +
		"contains the originator's IP addresses, directly mapping system IDs to " +
		"IPs for targeting; **LSP sequence numbers + overload bit** — sequence " +
		"number reveals router uptime and convergence history; overload bit " +
		"signals a router in maintenance (MITM candidate); **IS type (L1/L2/" +
		"L1L2)** — reveals the IS-IS level structure for targeted attack on " +
		"level-specific vulnerabilities.\n\n" +
		"Decodes:\n\n" +
		"- **8-byte IS-IS common header**: irpd (0x83), length_indicator, " +
		"version, id_length, pdu_type with 9-entry name table (L1_LAN_Hello " +
		"/ L2_LAN_Hello / P2P_Hello / L1_LSP / L2_LSP / L1_CSNP / L2_CSNP " +
		"/ L1_PSNP / L2_PSNP), version2, reserved, max_area_addresses.\n" +
		"- **LAN Hello (IIH) fixed fields** (PDU types 15+16): circuit_type, " +
		"source_id (6-byte system ID formatted as XXXX.XXXX.XXXX dotted hex), " +
		"holding_time, pdu_length, priority, lan_id.\n" +
		"- **P2P Hello fixed fields** (PDU type 17): circuit_type, source_id, " +
		"holding_time, pdu_length, local_circuit_id.\n" +
		"- **LSP fixed fields** (PDU types 18+20): pdu_length, " +
		"remaining_lifetime, lsp_id (hex), sequence_number, checksum, " +
		"overload_bit, is_type.\n" +
		"- **TLV walker**: type (1 byte) + length (1 byte) + value for all " +
		"TLVs; surfaces tlv_count and tlv_types list.\n" +
		"- **TLV 1 (Area Addresses)**: area_addresses[] in hex.\n" +
		"- **TLV 10 (Authentication)**: has_auth, auth_type with name " +
		"(Cleartext / HMAC-MD5 / CryptoAuth), is_cleartext_auth.\n" +
		"- **TLV 132 (IP Interface Address)**: ip_addresses[] in dotted-quad.\n" +
		"- **TLV 137 (Dynamic Hostname)**: hostname string.\n" +
		"- **Classification flags**: is_hello / is_lsp / is_csnp / is_psnp, " +
		"level (1 or 2 derived from PDU type).\n\n" +
		"Pure offline parser — paste IS-IS PDU bytes (after LLC/SNAP or HDLC " +
		"framing stripped) from tcpdump or Wireshark IS-IS dissector and get " +
		"the documented header + per-type body breakdown.\n\n" +
		"Out of scope: TLV 6 (IS Neighbors) deep parse; TLV 128/130 (IP " +
		"Internal/External Reachability); TLV 135 (Extended IP Reachability " +
		"wide metrics); TLV 232 (IPv6 Reachability); TLV 240 (Router " +
		"Capability); TLV 242 (Multi-Topology); checksum verification; " +
		"authentication material extraction (auth_type only — NEVER surfaces " +
		"auth_data); CSNP/PSNP LSP Entry TLV parsing; LLC/SNAP framing.\n\n" +
		"Source: gap analysis (ISP/enterprise IGP routing protocol — pairs " +
		"with eigrp_decode, ospf_packet_decode, and bgp_message_decode for " +
		"the complete routing protocol picture; IS-IS LSP injection is the " +
		"canonical ISP-scale MITM primitive). Wrap-vs-native: native — ISO " +
		"10589 + RFC 1195 are public; 8-byte binary common header + per-type " +
		"fixed fields + TLV chain; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"IS-IS PDU bytes as hex (raw PDU after LLC/SNAP or HDLC framing stripped). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   isisDecodeHandler,
}

func isisDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("isis_decode: 'hex' is required")
	}
	res, err := isis.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("isis_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
