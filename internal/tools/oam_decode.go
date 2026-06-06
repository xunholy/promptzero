// oam_decode.go — host-side Ethernet OAM / CFM (802.1ag / Y.1731) decoder
// Spec, delegating to internal/oam.
//
// Wrap-vs-native: native — a 4-byte CFM common header + an opcode-specific
// body + a TLV list; byte-field reads + an opcode switch, stdlib only.
// Adds the L2 service-topology / connectivity-fault leg to the LAN-attack
// family (dtp/vtp/vqp/gxrp/stp/maccontrol). Surfaces the CCM maintenance
// topology (MD level / MEG ID / MEP ID). Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/oam"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(oamDecodeSpec)
}

var oamDecodeSpec = Spec{
	Name: "oam_decode",
	Description: "Decode **Ethernet OAM / Connectivity Fault Management (CFM)** — IEEE 802.1ag / ITU-T Y.1731 " +
		"(EtherType 0x8902). An **L2 service-topology reconnaissance** source, joining the project's LAN " +
		"decoder family (`dtp`, `vtp`, `vqp`, `gxrp`, `stp`, `maccontrol`): the **Continuity Check Message " +
		"(CCM)** is a frame a maintenance endpoint multicasts continuously, advertising the Maintenance " +
		"Domain **level**, the Maintenance Entity Group (**MEG / MA**) identifier and the source **MEP ID** " +
		"— so a captured CCM stream maps the L2 maintenance topology (which bridges are MEPs, at which level, " +
		"in which association), and the **RDI** flag signals a remote defect. Loopback (LBM/LBR) and " +
		"Linktrace (LTM/LTR) are the L2 ping / traceroute of the same framework.\n\n" +
		"Decodes the 4-byte common header — MD **level**, version, the **opcode name** (all 24 CFM " +
		"functions: CCM / LBM / LBR / LTM / LTR / AIS / LCK / TST / APS / R-APS / LMM / DMM / SLM / …), the " +
		"flags byte and the TLV offset — for every opcode, and for a **CCM** additionally the RDI flag, the " +
		"transmission **period** (+ name), the **sequence number**, the **MEP ID** (13-bit) and the **MEG " +
		"ID** (raw + a best-effort printable extraction).\n\n" +
		"No confidently-wrong output: CFM has 24 opcodes with varied, often vendor-extended bodies, so only " +
		"the universally-present common header and the CCM body are decoded — every other opcode's body, and " +
		"the trailing TLV list, are surfaced as raw hex with the opcode named. No network, no device, " +
		"transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators and a '0x' prefix " +
		"tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (L2 connectivity-fault / service-topology recon). " +
		"Wrap-vs-native: native — a byte-field read + an opcode switch, stdlib only, no new go.mod dep. " +
		"Verified field-for-field against scapy's OAM layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The Ethernet OAM / CFM PDU (the EtherType-0x8902 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   oamDecodeHandler,
}

func oamDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("oam_decode: 'hex' is required")
	}
	res, err := oam.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("oam_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
