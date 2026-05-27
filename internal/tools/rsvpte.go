// rsvpte.go — host-side RSVP-TE wire-protocol decoder Spec.
// Wraps the internal/rsvpte walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rsvpte"
)

func init() { //nolint:gochecknoinits
	Register(rsvpteDecodeSpec)
}

var rsvpteDecodeSpec = Spec{
	Name: "rsvpte_decode",
	Description: "Decode an RSVP-TE (Resource Reservation Protocol — Traffic " +
		"Engineering) packet per RFC 3209 (RSVP-TE) and RFC 2205 (base " +
		"RSVP). RSVP-TE runs directly over IP (protocol number 46) — no " +
		"TCP/UDP wrapper. Establishes MPLS Label Switched Paths (LSPs) with " +
		"explicit routes and traffic engineering constraints. Used in ISP and " +
		"carrier backbone networks for MPLS TE, MPLS FRR (Fast Reroute), and " +
		"GMPLS optical transport.\n\n" +
		"RSVP-TE is the MPLS TE signalling protocol — **default RSVP has NO " +
		"authentication**. The INTEGRITY object (class 4, HMAC-MD5 keyed auth) " +
		"is optional and rarely deployed. Without it the control plane is fully " +
		"open to spoofing. **Path message injection creates unauthorized LSPs — " +
		"traffic redirection at MPLS TE scale. Resv message manipulation alters " +
		"label bindings — MITM at the switching plane.**\n\n" +
		"The wire format leaks: **SESSION objects** — tunnel_endpoint (IPv4) + " +
		"tunnel_id + extended_tunnel_id, exposing the full TE LSP setup; **ERO " +
		"(Explicit Route Object)** — the intended LSP path across the network, " +
		"mapping internal TE topology hop-by-hop; **RRO (Record Route Object)** " +
		"— the actual path traversed by the established LSP; **SESSION_ATTRIBUTE** " +
		"— LSP names, setup and holding priorities, full TE policy; " +
		"**SENDER_TEMPLATE / FILTER_SPEC** — sender IPv4 address + LSP ID, " +
		"mapping signalling relationships; **LABEL** — the MPLS label value " +
		"distributed for this LSP, enabling traffic interception at the " +
		"switching plane; **LABEL_REQUEST** — the L3PID (Layer 3 Protocol ID) " +
		"for which a label is requested, typically 0x0800 for IPv4; **HOP** — " +
		"the previous/next-hop address and logical interface handle, mapping " +
		"adjacencies; **TIME_VALUES** — the refresh period revealing keepalive " +
		"tuning.\n\n" +
		"Decodes:\n\n" +
		"- **8-byte RSVP common header**: version (4 bits) + flags (4 bits) + " +
		"msg_type (1 byte) with 11-entry name table (1 Path / 2 Resv / 3 " +
		"PathErr / 4 ResvErr / 5 PathTear / 6 ResvTear / 7 ResvConf / 10 " +
		"Bundle / 12 Hello / 13 Srefresh / 20 Notify) + checksum + send_ttl " +
		"+ reserved + rsvp_length.\n" +
		"- **Object walker**: length (2 BE) + class_num (1) + c_type (1) + " +
		"value[length-4] for all objects; surfaces object_count and " +
		"object_types[] (class_num + c_type + class_name for each).\n" +
		"- **SESSION (class 1, C-Type 7 = LSP_TUNNEL_IPv4)**: " +
		"tunnel_endpoint (dotted-quad) + tunnel_id + extended_tunnel_id.\n" +
		"- **HOP (class 3, C-Type 1)**: hop_address (dotted-quad) — " +
		"the next/previous-hop router address.\n" +
		"- **TIME_VALUES (class 5, C-Type 1)**: refresh_period_ms.\n" +
		"- **LABEL (class 16, C-Type 1)**: label_value — the MPLS label.\n" +
		"- **LABEL_REQUEST (class 19, C-Type 1)**: l3pid — the Layer 3 " +
		"Protocol ID (0x0800 = IPv4).\n" +
		"- **SENDER_TEMPLATE (class 11, C-Type 7)**: sender_address + lsp_id.\n" +
		"- **ERO (class 20)**: ero_hop_count + ero_hops[] (IPv4 address + " +
		"prefix_length + loose boolean) for IPv4 prefix sub-objects (type 1).\n" +
		"- **RRO (class 21)**: rro_hop_count — count of IPv4 recorded hops.\n" +
		"- **SESSION_ATTRIBUTE (class 207, C-Type 7)**: session_name + " +
		"setup_priority + holding_priority.\n" +
		"- **Classification flags**: is_path / is_resv / is_hello / " +
		"is_path_tear / is_resv_tear.\n\n" +
		"Pure offline parser — paste RSVP-TE packet bytes (IP protocol 46 " +
		"payload; stripped of IPv4 header) from `tcpdump proto 46` or " +
		"Wireshark RSVP dissector and get the documented header + per-object " +
		"body breakdown.\n\n" +
		"Out of scope: INTEGRITY object authentication material (auth_type only " +
		"— NEVER surfaces auth_data); FLOWSPEC + SENDER_TSPEC traffic " +
		"specification parsing; STYLE + RESV_CONFIRM objects; IPv6 address " +
		"variants in objects; GMPLS generalized label formats; checksum " +
		"verification; IP framing (feed bytes after IPv4 header strip).\n\n" +
		"Source: gap analysis (MPLS TE signalling — canonical ISP/carrier " +
		"backbone control-plane protocol; pairs with mpls_decode + ldp_decode " +
		"for the complete MPLS control + data-plane picture; RSVP-TE LSP " +
		"injection is the MPLS-backbone MITM primitive). Wrap-vs-native: " +
		"native — RFC 2205 and RFC 3209 are public; 8-byte binary header + " +
		"object chain; no crypto at the parse layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"RSVP-TE packet bytes as hex (the IP protocol 46 payload after IPv4 header strip). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rsvpteDecodeHandler,
}

func rsvpteDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("rsvpte_decode: 'hex' is required")
	}
	res, err := rsvpte.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("rsvpte_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
