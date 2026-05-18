// zigbee_zcl.go — host-side Zigbee Cluster Library (ZCL) frame
// dissector Spec, delegating to the internal/zigbee package for
// the walker proper.

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
	Register(zigbeeZCLDecodeSpec)
}

var zigbeeZCLDecodeSpec = Spec{
	Name: "zigbee_zcl_decode",
	Description: "Decode a Zigbee Cluster Library (ZCL) frame — the application layer that " +
		"sits on top of APS in the Zigbee stack (MAC → NWK → APS → ZCL). This is where real " +
		"application commands live: On/Off, Level Control, Temperature Measurement, Battery, " +
		"Identify. Decodes:\n\n" +
		"- **Frame Control** (8 bits): frame type (Profile-wide vs Cluster-specific), " +
		"manufacturer-specific flag, direction (Client→Server vs Server→Client), disable-" +
		"default-response flag.\n" +
		"- **Manufacturer Code** (2 bytes, when flag set): the SIG-assigned 16-bit " +
		"manufacturer identifier for vendor-specific commands.\n" +
		"- **Transaction Sequence Number** (1 byte): links request → response across ZCL " +
		"exchanges.\n" +
		"- **Command ID** (1 byte): the cluster command being invoked. For Profile-wide " +
		"frames, looks up the canonical name from the documented catalog (Read Attributes, " +
		"Report Attributes, Default Response, Configure Reporting, Discover Attributes, etc.). " +
		"Cluster-specific commands need the APS-layer Cluster ID for context; we surface the " +
		"command ID + payload for the operator to cross-reference.\n" +
		"- **Payload**: command body bytes (uppercase hex).\n\n" +
		"Pure offline parser — operators chain ieee802154_decode → zigbee_nwk_decode → " +
		"zigbee_aps_decode → zigbee_zcl_decode for full Zigbee frame analysis from the radio " +
		"bytes up to the cluster command. Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (2.4 GHz IoT decode space — completes the Zigbee " +
		"stack chain). Wrap-vs-native: native — ZCL is a fully public spec (Zigbee Cluster " +
		"Library Specification 07-5123-08), the walker is bit-level decoding over a 3-byte " +
		"minimum header + variable payload.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded Zigbee ZCL frame (the APS payload from a decoded APS frame). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   zigbeeZCLDecodeHandler,
}

func zigbeeZCLDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("zigbee_zcl_decode: 'hex' is required")
	}
	res, err := zigbee.DecodeZCL(raw)
	if err != nil {
		return "", fmt.Errorf("zigbee_zcl_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
