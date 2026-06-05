// dtp_decode.go — host-side Cisco Dynamic Trunking Protocol decoder Spec,
// delegating to internal/dtp.
//
// Wrap-vs-native: native — a DTP PDU is a version octet + 4-octet-header
// TLVs in an LLC/SNAP frame (OUI 0x00000C, PID 0x2004); a short TLV walk.
// Joins the switch-L2 decoder set (cdp/lldp/stp/lacp/vlan/macsec). The
// VLAN-hopping attack-surface signal. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/dtp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(dtpDecodeSpec)
}

var dtpDecodeSpec = Spec{
	Name: "dtp_decode",
	Description: "Decode Cisco's **Dynamic Trunking Protocol** (DTP) — the L2 protocol a Cisco switch port uses " +
		"to negotiate whether a link becomes an 802.1Q / ISL **trunk**. DTP is the basis of the classic " +
		"**VLAN-hopping** attack: a port left in a negotiating mode (dynamic desirable / dynamic auto — the " +
		"default on many switches) can be talked into forming a trunk by a rogue host, giving it reach into " +
		"every VLAN. Decoding a captured DTP frame surfaces the **VTP domain name**, the **neighbour MAC** " +
		"and the raw trunk-negotiation status — the reconnaissance a switch-security audit needs. Joins the " +
		"switch / L2 decoder set (`cdp`, `lldp`, `stp`, `lacp`, `vlan_decode`, `macsec_decode`).\n\n" +
		"Decodes the PDU: the **version**, and the **Domain** (0x0001 → the VTP domain, an info leak), " +
		"**Status** (0x0002), **DTP/Trunk-Type** (0x0003) and **Neighbour** (0x0004 → MAC) TLVs; unknown " +
		"TLVs are surfaced raw. Accepts the PDU itself (from the version octet) or any frame containing the " +
		"LLC/SNAP DTP signature (OUI 0x00000C, PID 0x2004) — the bytes after it are decoded.\n\n" +
		"No confidently-wrong output: DTP is Cisco-proprietary and **reverse-engineered**, and its status-bit " +
		"semantics (the exact dynamic-desirable / dynamic-auto / trunk encoding) are not authoritatively " +
		"standardised, so the **status and trunk-type octets are surfaced raw** (hex + decimal) rather than " +
		"decoded into a named mode that could be wrong. What IS stated with certainty: the presence of DTP " +
		"means the port is participating in trunk negotiation (not 'nonegotiate') — the VLAN-hopping " +
		"prerequisite.\n\n" +
		"Offline transform — reads the bytes, transmits nothing, so it is Low risk. ':' / '-' / '_' / " +
		"whitespace separators and a '0x' prefix tolerated. Source: docs/catalog/gap-analysis.md (switch-L2 " +
		"VLAN-hopping recon). Wrap-vs-native: native — TLV walk, stdlib only, no new go.mod dep. Verified " +
		"field-for-field against scapy's DTP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"A DTP PDU as hex (from the version octet), or a frame containing the LLC/SNAP DTP signature (00000C 2004). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   dtpDecodeHandler,
}

func dtpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("dtp_decode: 'hex' is required")
	}
	res, err := dtp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("dtp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
