// zigbee_attribute.go — host-side Zigbee ZCL attribute-value
// type dissector Spec, delegating to the internal/zigbee
// package for the walker proper.

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
	Register(zigbeeZCLAttributeDecodeSpec)
}

var zigbeeZCLAttributeDecodeSpec = Spec{
	Name: "zigbee_zcl_attribute_decode",
	Description: "Decode a Zigbee ZCL attribute value (type tag + value bytes) per ZCL Spec " +
		"§2.5.2 Table 2-10. Handles the ~30 documented data types:\n\n" +
		"- **Null / unknown** (0x00 / 0xFF): zero-length values.\n" +
		"- **Generic data** (0x08-0x0B): 8 / 16 / 24 / 32-bit raw values.\n" +
		"- **Boolean** (0x10): single byte true/false.\n" +
		"- **Bitmaps** (0x18 / 0x19 / 0x1B): 8 / 16 / 32-bit bitmap values.\n" +
		"- **Unsigned integers** (0x20-0x27): uint8 / uint16 / uint24 / uint32 / uint64.\n" +
		"- **Signed integers** (0x28-0x2F): int8 / int16 / int32 / int64.\n" +
		"- **Enumerations** (0x30 / 0x31): 8 / 16-bit enum values.\n" +
		"- **Floats** (0x38 / 0x39 / 0x3A): semi-precision (16-bit half) / single / double.\n" +
		"- **Strings** (0x41 / 0x42 / 0x43 / 0x44): octet string + char string with 1-byte " +
		"length prefix; long variants with 2-byte length prefix.\n" +
		"- **Time** (0xE0): time of day (HH:MM:SS.SS).\n" +
		"- **Date** (0xE1): year-1900 / month / day / day-of-week.\n" +
		"- **UTC time** (0xE2): 32-bit seconds since 2000-01-01.\n" +
		"- **Cluster ID** (0xE8): 16-bit cluster identifier hex.\n" +
		"- **Attribute ID** (0xE9): 16-bit attribute identifier hex.\n" +
		"- **BACnet OID** (0xEA): 32-bit BACnet object identifier.\n" +
		"- **IEEE address** (0xF0): 8-byte EUI-64 (LE on wire, BE rendered).\n" +
		"- **Security key** (0xF1): 128-bit network/link key.\n\n" +
		"Pure offline parser — operators with a Read Attributes Response / Report Attributes / " +
		"Write Attributes payload paste each attribute's (type + value) bytes and get a " +
		"structured value back. Returns the bytes-consumed count so callers walking " +
		"multi-attribute payloads can advance the offset. Pairs with zigbee_zcl_decode (the " +
		"frame walker that surfaces the payload).\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (Zigbee application-layer decode space). " +
		"Wrap-vs-native: native — ZCL Spec 07-5123-08 §2.5.2 is fully public, the walker is a " +
		"type-byte dispatch with per-type value decoders.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded ZCL attribute value (1-byte data type tag + value bytes). ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   zigbeeZCLAttributeDecodeHandler,
}

func zigbeeZCLAttributeDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("zigbee_zcl_attribute_decode: 'hex' is required")
	}
	res, _, err := zigbee.DecodeAttribute(raw)
	if err != nil {
		return "", fmt.Errorf("zigbee_zcl_attribute_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
