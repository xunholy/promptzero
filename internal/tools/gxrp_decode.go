// gxrp_decode.go — host-side GARP / GVRP / GMRP (IEEE 802.1D dynamic
// VLAN / multicast registration) decoder Spec, delegating to internal/gxrp.
//
// Wrap-vs-native: native — a 2-byte protocol id + nested message /
// attribute lists with 0x00 end-marks; byte-field reads + two walks,
// stdlib only. The fourth leg of the Cisco/L2 VLAN-attack family with
// dtp + vtp + vqp. Surfaces the VLANs / multicast groups being
// registered — a GVRP VLAN-hopping primitive. Offline read.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/gxrp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gxrpDecodeSpec)
}

var gxrpDecodeSpec = Spec{
	Name: "gxrp_decode",
	Description: "Decode **GARP / GVRP / GMRP** (Generic Attribute Registration Protocol, IEEE 802.1D-2004 — " +
		"and its applications GARP **VLAN** Registration Protocol and GARP **Multicast** Registration " +
		"Protocol). The fourth leg of the project's Cisco/L2 **VLAN-attack** decoder family alongside `dtp` " +
		"(trunk-negotiation VLAN-hopping), `vtp` (VLAN-database tampering) and `vqp` (VMPS VLAN assignment): " +
		"**GVRP dynamic VLAN registration is an L2 attack surface** — a host that emits GVRP **JoinIn** " +
		"attributes can register arbitrary VLANs onto the trunk it is attached to (extending the trunk's " +
		"allowed-VLAN set), a VLAN-hopping primitive; GMRP does the equivalent for multicast group " +
		"membership. A captured PDU reveals which VLANs / multicast groups are being registered or withdrawn " +
		"and by which **event** (Join / Leave / LeaveAll).\n\n" +
		"Decodes the GARP framing — protocol id, and the nested list of **messages** (each a type + a list of " +
		"**attributes**: length, event + name, value). The attribute value is interpreted by length: a 2-byte " +
		"value is a **VLAN id** (GVRP), a 6-byte value a **group MAC** (GMRP), a 1-byte value a **GMRP " +
		"service**.\n\n" +
		"No confidently-wrong output: the GVRP-vs-GMRP application is keyed in the standard by the L2 " +
		"destination MAC (not carried in the PDU), so the attribute kind is **inferred from the value length** " +
		"(the lengths are non-overlapping and deterministic) and the **raw value is always surfaced** " +
		"alongside, with a note naming the definitive signal; unknown value lengths are surfaced as raw hex " +
		"only. No network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace " +
		"separators and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (GVRP/GMRP dynamic VLAN/multicast-registration recon). " +
		"Wrap-vs-native: native — a byte-field read + two nested walks, stdlib only, no new go.mod dep. " +
		"Verified field-for-field against scapy's GARP layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The GARP/GVRP/GMRP PDU (the LLC payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gxrpDecodeHandler,
}

func gxrpDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("gxrp_decode: 'hex' is required")
	}
	res, err := gxrp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("gxrp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
