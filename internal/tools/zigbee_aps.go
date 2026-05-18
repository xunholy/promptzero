// zigbee_aps.go — host-side Zigbee APS (Application Support
// sublayer) frame dissector Spec, delegating to the
// internal/zigbee package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/risk"
	"github.com/xunholy/promptzero/internal/zigbee"
)

func init() { //nolint:gochecknoinits
	Register(zigbeeAPSDecodeSpec)
}

var zigbeeAPSDecodeSpec = Spec{
	Name: "zigbee_aps_decode",
	Description: "Decode a Zigbee APS (Application Support sublayer) frame — sits on top of " +
		"the Zigbee NWK layer in the Zigbee stack (MAC → NWK → APS → ZCL). Decodes:\n\n" +
		"- **Frame Control** (8 bits): frame type (Data / APS Command / Acknowledge / " +
		"Inter-PAN), delivery mode (Unicast / Indirect / Broadcast / Group), ack format / " +
		"security / ack request / extended header flags.\n" +
		"- **Addressing** (Data + Ack frames): 1-byte destination endpoint (or 2-byte group " +
		"address for Group delivery), 2-byte Cluster ID, 2-byte Profile ID with well-known " +
		"profile name lookup (ZDP, HA, SE, ZLL, Smart Energy, Green Power), 1-byte source " +
		"endpoint.\n" +
		"- **APS Counter**: 1-byte sequence counter (present on all frames).\n" +
		"- **Extended Header** (when flag set): 3-byte fragmentation header (type + block " +
		"number + ack bitfield) surfaced as hex.\n" +
		"- **Aux Security Header** (when flag set): same shape as the NWK security header, " +
		"sized via the security control byte (KeyID + extended-nonce flag).\n" +
		"- **APS Payload**: surfaced as hex; ZCL dissection deferred to follow-on Specs.\n\n" +
		"Pure offline parser — operators chain ieee802154_decode → zigbee_nwk_decode → " +
		"zigbee_aps_decode for full Zigbee MAC + NWK + APS frame analysis. Accepts ':' / '-' " +
		"/ '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (2.4 GHz IoT decode space). Wrap-vs-native: " +
		"native — Zigbee APS is a fully public spec, the walker is bit-level decoding over a " +
		"~10-byte header + variable payload.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Zigbee APS frame (the NWK payload from a decoded NWK frame). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   zigbeeAPSDecodeHandler,
}

func zigbeeAPSDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("zigbee_aps_decode: 'hex' is required")
	}
	res, err := zigbee.DecodeAPS(raw)
	if err != nil {
		return "", fmt.Errorf("zigbee_aps_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
