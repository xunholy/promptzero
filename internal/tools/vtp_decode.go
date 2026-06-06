// vtp_decode.go — host-side Cisco VLAN Trunking Protocol decoder Spec,
// delegating to internal/vtp.
//
// Wrap-vs-native: native — a VTP PDU is a fixed header + a per-code body
// in an LLC/SNAP frame (OUI 0x00000C, PID 0x2003); byte-field extraction
// + a record walk. Joins the switch-L2 set (cdp/lldp/stp/lacp/vlan/
// macsec/dtp). Surfaces the config-revision attack signal. Offline read.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/vtp"
)

func init() { //nolint:gochecknoinits
	Register(vtpDecodeSpec)
}

var vtpDecodeSpec = Spec{
	Name: "vtp_decode",
	Description: "Decode Cisco's **VLAN Trunking Protocol** (VTP) — the L2 protocol that synchronises the VLAN " +
		"database across the switches of a VTP domain. VTP is a notorious switch-security hazard: a VTP " +
		"server (or a rogue host that can reach a trunk) advertising a **higher configuration-revision " +
		"number** overwrites every switch's VLAN database in the domain — a Subset advertisement with a high " +
		"revision and a forged/empty VLAN list deletes or rewrites all VLANs domain-wide (a classic L2 " +
		"denial-of-service). Decoding a captured VTP frame surfaces the **domain name**, the message type, " +
		"and the all-important **configuration revision** — the recon a switch-security audit needs. Joins " +
		"the switch / L2 decoder set (`cdp`, `lldp`, `stp`, `lacp`, `vlan_decode`, `macsec_decode`, " +
		"`dtp_decode`).\n\n" +
		"Decodes the header (version, message **code** — Summary / Subset / Advertisement-Request / Join — " +
		"and the **domain name**) and the bodies:\n" +
		"- **Summary Advertisement**: followers, the **config revision**, the updater identity (IPv4), the " +
		"update timestamp, and the MD5 digest.\n" +
		"- **Subset Advertisement**: sequence number, the config revision, and the full **VLAN list** (each " +
		"VLAN's id, name, status, type and MTU) — switch-recon gold.\n\n" +
		"Accepts the PDU itself or any frame carrying the LLC/SNAP VTP signature (OUI 0x00000C, PID 0x2003). " +
		"No confidently-wrong output: the **MD5 digest is surfaced as hex and NOT verified** — it is computed " +
		"over the VLAN database + the VTP password, which is not on the wire; Advertisement-Request / Join " +
		"bodies are surfaced raw. No network, no device, transmits nothing, so it is Low risk.\n\n" +
		"Source: docs/catalog/gap-analysis.md (switch-L2 VLAN-database-attack recon). Wrap-vs-native: " +
		"native — byte-field extraction + a record walk, stdlib only, no new go.mod dep. Verified " +
		"field-for-field against scapy's VTP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"A VTP PDU as hex, or a frame carrying the LLC/SNAP VTP signature (00000C 2003). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   vtpDecodeHandler,
}

func vtpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("vtp_decode: 'hex' is required")
	}
	res, err := vtp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("vtp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
