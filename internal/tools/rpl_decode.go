// rpl_decode.go — host-side RPL (RFC 6550, IPv6 routing for low-power IoT
// mesh) decoder Spec, delegating to internal/rpl.
//
// Wrap-vs-native: native — the RPL control messages are fixed
// bitfield/byte layouts inside an ICMPv6 type-155 message; field
// extraction + bit-masking, stdlib only. The IoT-routing companion to
// ieee802154 / zigbee. Surfaces the DIO rank + version — the
// sinkhole / version-rebuild attack fields. Offline read, no hardware.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/rpl"
)

func init() { //nolint:gochecknoinits
	Register(rplDecodeSpec)
}

var rplDecodeSpec = Spec{
	Name: "rpl_decode",
	Description: "Decode **RPL** (Routing Protocol for Low-Power and Lossy Networks, RFC 6550) — the IPv6 routing " +
		"protocol that builds the mesh (\"DODAG\") of a **6LoWPAN / IEEE 802.15.4 IoT network**, carried in " +
		"**ICMPv6 type 155**. A recognised **IoT-routing attack** surface: a malicious node can advertise a " +
		"forged low **rank** in a DIO to pull the mesh's traffic through itself (a **sinkhole / on-path** " +
		"attack), or bump the DODAG **version** to force a costly network-wide rebuild (a **DoS**) — both are " +
		"visible in a captured DIO. Joins the project's IoT decoders (`ieee802154`, `zigbee`, `ndp`).\n\n" +
		"Decodes the ICMPv6 RPL header (type + **message name**: DIS / DIO / DAO / DAO-ACK) and, for a **DIO**, " +
		"the RPLInstanceID, **version**, **rank**, Grounded flag, **Mode of Operation** (+ name), DODAG " +
		"preference, DTSN and **DODAGID**; for **DAO / DAO-ACK**, the InstanceID, sequence, status and " +
		"DODAGID. The headline rank + version fields are surfaced with an attack note.\n\n" +
		"No confidently-wrong output: only the fixed message header is decoded — the trailing RPL options " +
		"(DODAG Config, Prefix / Transit / Target info) are a varied TLV list and are surfaced as raw hex; " +
		"the ICMPv6 checksum (which covers an IPv6 pseudo-header not present here) is not verified. No " +
		"network, no device, transmits nothing, so it is Low risk. ':' / '-' / '_' / whitespace separators " +
		"and a '0x' prefix tolerated.\n\n" +
		"Source: docs/catalog/gap-analysis.md (6LoWPAN / RPL IoT-mesh routing recon). Wrap-vs-native: " +
		"native — bitfield/byte extraction, stdlib only, no new go.mod dep. Verified field-for-field against " +
		"scapy's RPL layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"The ICMPv6 RPL message (type 155) as hex. ':' '-' '_' whitespace separators and a '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   rplDecodeHandler,
}

func rplDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	if strings.TrimSpace(str(p, "hex")) == "" {
		return "", fmt.Errorf("rpl_decode: 'hex' is required")
	}
	res, err := rpl.Decode(str(p, "hex"))
	if err != nil {
		return "", fmt.Errorf("rpl_decode: %w", err)
	}
	body, _ := json.MarshalIndent(res, "", "  ")
	return string(body), nil
}
