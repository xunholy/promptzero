// homepluggp_decode.go — host-side HomePlug Green PHY SLAC (EV-charging
// pairing) management-message decoder Spec, delegating to internal/homepluggp.
//
// Wrap-vs-native: native — a 1-byte version + 2-byte little-endian MMTYPE
// envelope (shared with HomePlug AV) + a fixed-layout SLAC body; a byte-slice
// walk + an MMTYPE lookup, stdlib only. The EV-charging association decoder —
// surfaces the SLAC handshake step, the session Run ID, the EV / EVSE MACs
// and IDs, and the NID + NMK key material from a captured Control-Pilot
// powerline frame. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/homepluggp"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(homePlugGPDecodeSpec)
}

var homePlugGPDecodeSpec = Spec{
	Name: "homepluggp_decode",
	Description: "Decode a **HomePlug Green PHY SLAC** management message — the Signal Level Attenuation " +
		"Characterization protocol that pairs an **electric vehicle to a charging station** over the CCS / " +
		"ISO 15118 (DIN 70121) Combined Charging System. Before any high-level EV ↔ EVSE communication, the " +
		"two sides run SLAC over HomePlug Green PHY (a powerline / PLC link on the Control Pilot line) to work " +
		"out which charger the car is physically plugged into and to establish a private logical network. SLAC " +
		"is a hot **EV-charging-security** topic: the handshake is unauthenticated, matching is " +
		"attenuation-based (attackable by signal injection), and the **match / set-key** messages carry the " +
		"powerline Network Membership Key (NMK) in the clear — capturing one yields the charging link's " +
		"network credential.\n\n" +
		"A captured SLAC frame identifies the **step** of the pairing handshake (SLAC-parm → start-atten → " +
		"M-sound → atten-char → match → set-key) and surfaces the session **Run ID**, the **EV / EVSE MAC " +
		"addresses and IDs**, and — for CM_SLAC_MATCH.CNF / CM_SET_KEY — the **NID + NMK** key material, which " +
		"is the recon headline.\n\n" +
		"Extends the powerline domain of homeplugav: those are the 0xAxxx vendor MMEs (HomePlug AV adapters); " +
		"these are the 0x60xx CCo SLAC MMEs (HomePlug Green PHY EV charging). Both ride EtherType 0x88E1.\n\n" +
		"No confidently-wrong output: the envelope and SLAC body layouts are verified field-for-field against " +
		"scapy's HomePlug Green PHY layer and ISO 15118-3; unlike vendor HomePlug AV bodies (surfaced raw), the " +
		"SLAC bodies are standardised so the recon fields are decoded. Each decode is length-gated — a body " +
		"that does not match the SLAC layout is surfaced raw with a note, and a non-SLAC MMTYPE is rejected. No " +
		"network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators and " +
		"a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (powerline / EV-charging SLAC recon). Wrap-vs-native: native — a " +
		"byte-slice walk + an MMTYPE lookup, stdlib only, no new go.mod dep.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The HomePlug Green PHY SLAC management message (the EtherType-0x88E1 payload) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   homePlugGPDecodeHandler,
}

func homePlugGPDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("homepluggp_decode: 'hex' is required")
	}
	res, err := homepluggp.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("homepluggp_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
