// gtpv2_decode.go — host-side GTPv2-C (GTP control plane) decoder Spec,
// delegating to internal/gtpv2.
//
// Wrap-vs-native: native — the GTPv2-C header is a fixed bitfield + a TLV
// IE list (3GPP TS 29.274); byte-field extraction + a TLV walk. The
// control-plane companion to gtp_decode (GTP-U), which defers GTP-C.
// Surfaces the IMSI/MSISDN/MEI harvesting exposure. Offline read.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/gtpv2"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(gtpv2DecodeSpec)
}

var gtpv2DecodeSpec = Spec{
	Name: "gtpv2_decode",
	Description: "Decode **GTPv2-C** — the GTP version-2 **control plane** (3GPP TS 29.274) that signals EPS " +
		"bearer / session management across the LTE and 5G-NSA core (the S11 MME↔SGW, S5/S8 SGW↔PGW and " +
		"S10/S16 interfaces, UDP 2123). The **control-plane companion to `gtp_decode`**, which decodes the " +
		"GTP-U user plane and explicitly defers GTP-C. GTP-C is a recognised telecom-security target: the " +
		"roaming / core GTP plane has been abused for **IMSI harvesting**, subscriber tracking and the " +
		"GTPdoor backdoor, and a captured Create-Session / Modify-Bearer exchange carries the subscriber's " +
		"**IMSI, MSISDN and MEI in the clear**.\n\n" +
		"Decodes the header (version, the piggyback / TEID / message-priority flags, the **message type** " +
		"with a TS 29.274 name table — Create/Modify/Delete Session, Create/Update/Delete Bearer, etc. — the " +
		"length, the optional **TEID**, and the sequence number) and the body as a list of **Information " +
		"Elements** (each TLV's type — named from the TS 29.274 table — length, instance and value). The " +
		"**TBCD-encoded subscriber identifiers IMSI / MSISDN / MEI are decoded to their digit strings** (the " +
		"headline for the IMSI-harvesting use case); every other IE value is surfaced as raw hex.\n\n" +
		"No confidently-wrong output: only the TBCD identifiers + the Cause code are decoded — the IE value " +
		"formats are many and version-specific, so the rest are left raw rather than guessed. No network, no " +
		"device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators and a '0x' " +
		"prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (cellular control-plane decode — the GTP-C gap deferred by " +
		"gtp_decode). Wrap-vs-native: native — byte-field extraction + a TLV walk, stdlib only, no new " +
		"go.mod dep. Verified field-for-field against scapy's GTPv2 layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"A GTPv2-C message as hex (the GTP-C payload of UDP 2123). ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   gtpv2DecodeHandler,
}

func gtpv2DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("gtpv2_decode: 'hex' is required")
	}
	res, err := gtpv2.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("gtpv2_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
