// vqp_decode.go — host-side Cisco VQP / VMPS (dynamic VLAN assignment)
// decoder Spec, delegating to internal/vqp.
//
// Wrap-vs-native: native — an 8-byte header + a type(4)+len(2)+value
// TLV walk; byte-field extraction, stdlib only. The third leg of the
// Cisco VLAN-attack family alongside dtp (VLAN-hopping) and vtp
// (VLAN-DB tampering). Surfaces the queried MAC + assigned VLAN — the
// voiphopper / yersinia VLAN-assignment attack surface. Offline read.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vqp"
)

func init() { //nolint:gochecknoinits
	Register(vqpDecodeSpec)
}

var vqpDecodeSpec = Spec{
	Name: "vqp_decode",
	Description: "Decode **Cisco VQP** (VLAN Query Protocol) — the wire protocol of **VMPS** (VLAN Membership " +
		"Policy Server), by which a switch asks a server \"what VLAN should this source MAC be put on?\" and " +
		"the server answers with a VLAN name (UDP 1589). The third leg of the project's **Cisco VLAN-attack** " +
		"decoder family alongside `dtp` (DTP trunk-negotiation VLAN-hopping) and `vtp` (VTP VLAN-database " +
		"tampering): dynamic VLAN assignment by MAC is an attack surface — a host that **spoofs a MAC the " +
		"server maps to a privileged VLAN** (e.g. a voice / management VLAN — the voiphopper / yersinia " +
		"technique) lands its port in that VLAN, and a server that answers with **shutdownPort / accessDenied** " +
		"is the lockout response. A captured exchange reveals the queried **MAC**, the switch **port**, the " +
		"VTP **domain** and the assigned **VLAN name**.\n\n" +
		"Decodes the 8-byte header (version, **opcode** — requestPort / responseVLAN / requestReconfirm / " +
		"responseReconfirm, **response code** — none / accessDenied / shutdownPort / wrongDomain, flag, " +
		"sequence) and the list of **data entries** (each datatype + length + value): clientIPAddress → IPv4, " +
		"Req/ResMACAddress → MAC, portName / VLANName / Domain → text. A denied response is flagged.\n\n" +
		"No confidently-wrong output: typed entries are decoded by datatype; the ethernetPacket / unknown " +
		"entry bodies (and any non-printable name) are surfaced as raw hex. No network, no device, transmits " +
		"nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Cisco VLAN-assignment / VMPS recon). Wrap-vs-native: native — " +
		"a byte-field read + a TLV walk, stdlib only, no new go.mod dep. Verified field-for-field against " +
		"scapy's VQP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The VQP message (the UDP-1589 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vqpDecodeHandler,
}

func vqpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("vqp_decode: 'hex' is required")
	}
	res, err := vqp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("vqp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
