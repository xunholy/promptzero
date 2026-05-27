// ldp.go — host-side LDP wire-protocol decoder Spec.
// Wraps the internal/ldp walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/ldp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(ldpDecodeSpec)
}

var ldpDecodeSpec = Spec{
	Name: "ldp_decode",
	Description: "Decode an LDP (Label Distribution Protocol) PDU per RFC " +
		"5036. LDP runs on TCP/646 (session messages) and UDP/646 (Hello " +
		"discovery). It distributes MPLS label bindings between Label " +
		"Switching Routers (LSRs), forming the control plane of MPLS " +
		"networks.\n\n" +
		"LDP is the **MPLS control plane** — it distributes label bindings " +
		"that govern packet forwarding at the MPLS switching layer. " +
		"**Default LDP has NO authentication** — TCP/646 sessions are " +
		"unauthenticated. TCP MD5 authentication (RFC 2385) is optional " +
		"and often omitted. LDP session hijacking allows label manipulation " +
		"— traffic redirection at the MPLS layer without touching IP " +
		"routing.\n\n" +
		"The wire format leaks: **LSR IDs** (router loopback IPs — the " +
		"primary LDP transport endpoint identifier; disclosed in every PDU " +
		"header); **transport addresses** (IPv4 Transport Address TLV " +
		"0x0501 — identifies the TCP endpoint for the LDP session); " +
		"**Hello parameters** (hold_time + targeted flag — targeted Hello " +
		"signals RSVP-TE or LDP over non-directly-connected links); " +
		"**label bindings** (Generic Label TLV 0x0300 in Label Mapping " +
		"messages — the FEC-to-label binding table); **session parameters** " +
		"(keepalive_time, max_pdu_length, receiver LSR ID — the full " +
		"session negotiation). LDP is the signalling protocol for MPLS " +
		"VPNs (L3VPN, L2VPN, VPLS). Compromising LDP = compromising the " +
		"MPLS switching plane.\n\n" +
		"Decodes:\n\n" +
		"- **10-byte LDP PDU header**: version (must be 1) + pdu_length + " +
		"lsr_id (dotted-quad) + label_space.\n" +
		"- **LDP message header**: message_type (15-bit, unknown_bit masked) " +
		"with 13-entry name table (Notification 0x0001 / Hello 0x0100 / " +
		"Initialization 0x0200 / KeepAlive 0x0201 / Address 0x0300 / " +
		"Address Withdraw 0x0301 / Label Mapping 0x0400 / Label Request " +
		"0x0401 / Label Withdraw 0x0402 / Label Release 0x0403 / Label " +
		"Abort Request 0x0404) + message_length + message_id.\n" +
		"- **TLV walker**: unknown_bit(1) + forward_bit(1) + type(14 bits " +
		"BE) + length(2 BE) + value for all TLVs in the first message; " +
		"surfaces tlv_count.\n" +
		"- **Common Hello Parameters TLV (0x0500)**: hold_time (seconds) + " +
		"targeted (T-bit — signals RSVP-TE or non-directly-connected LDP " +
		"session) + request_targeted (R-bit).\n" +
		"- **IPv4 Transport Address TLV (0x0501)**: transport_address " +
		"(dotted-quad — the LSR's LDP TCP endpoint).\n" +
		"- **Common Session Parameters TLV (0x0600)**: keepalive_time + " +
		"max_pdu_length + receiver_lsr_id (dotted-quad).\n" +
		"- **Generic Label TLV (0x0300)**: label_value (low 20 bits of " +
		"4-byte field — the MPLS label).\n" +
		"- **Classification flags**: is_hello / is_initialization / " +
		"is_keepalive / is_label_mapping / is_notification.\n\n" +
		"Pure offline parser — paste LDP PDU bytes (TCP/646 or UDP/646 " +
		"payload) from tcpdump `port 646` or Wireshark LDP dissector and " +
		"get the documented PDU header + per-message breakdown.\n\n" +
		"Out of scope: FEC TLV (0x0001) element dispatch; Address List TLV " +
		"(0x0100); Status TLV (0x0400) in Notification messages; ATM Label " +
		"/ Frame Relay Label TLVs; Path Vector / Hop Count TLVs; multiple " +
		"PDUs per buffer (first PDU only); TCP MD5 authentication " +
		"(operates at TCP layer, outside LDP PDU bytes).\n\n" +
		"Source: RFC 5036 (MPLS control-plane signalling — the label- " +
		"distribution protocol that pairs with mpls_decode for the " +
		"complete MPLS-layer picture; LDP label injection is the canonical " +
		"MPLS MITM primitive on unauthenticated provider networks). " +
		"Wrap-vs-native: native — RFC 5036 is public; 10-byte binary PDU " +
		"header + 8-byte message header + TLV chain; no crypto at the " +
		"parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"LDP PDU bytes as hex (the TCP/646 or UDP/646 payload). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   ldpDecodeHandler,
}

func ldpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("ldp_decode: 'hex' is required")
	}
	res, err := ldp.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("ldp_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
