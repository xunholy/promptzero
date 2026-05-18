// coap.go — host-side CoAP packet dissector Spec, delegating
// to the internal/coap package for the walker proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/coap"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(coapPacketDecodeSpec)
}

var coapPacketDecodeSpec = Spec{
	Name: "coap_packet_decode",
	Description: "Decode a Constrained Application Protocol (CoAP, RFC 7252) packet — the " +
		"application-layer protocol used by constrained IoT devices (6LoWPAN, Thread, " +
		"OpenThread, Zigbee IP). Decodes:\n\n" +
		"- **Fixed header**: 2-bit version + 2-bit type (Confirmable / Non-Confirmable / " +
		"Acknowledgement / Reset) + 4-bit token length (0..8) + 8-bit code + 16-bit big-" +
		"endian message ID.\n" +
		"- **Code**: standard CoAP 'c.dd' notation (0.01 GET, 0.02 POST, 0.03 PUT, 0.04 " +
		"DELETE, 0.05 FETCH, 0.06 PATCH, 0.07 iPATCH; 2.01-2.05 + 2.31 success codes; " +
		"4.00-4.15 client errors with documented names; 5.00-5.05 server errors).\n" +
		"- **Token** (0-8 bytes): for request-response correlation.\n" +
		"- **Options**: delta + length nibble encoding (extensions 13 = +1 byte / 14 = +2 " +
		"byte). Per-option-number name lookup for the documented options (Uri-Host / " +
		"Uri-Port / Uri-Path / Uri-Query / Content-Format / Accept / Max-Age / ETag / " +
		"If-Match / If-None-Match / Location-Path / Location-Query / Observe / Block1 / " +
		"Block2 / Size1 / Size2 / Proxy-Uri / Proxy-Scheme). Per-type value " +
		"interpretation (string for path/query options, uint for port/format/observe/block).\n" +
		"- **Payload**: surfaced after the 0xFF marker, both as hex and as printable-ASCII " +
		"string when applicable.\n\n" +
		"Pure offline parser — operators paste a captured CoAP packet from Wireshark / any " +
		"UDP sniffer and inspect every field without re-running the capture. Pairs with the " +
		"existing IoT decoders (mqtt_packet_decode for the IP-side broker protocol, " +
		"zigbee_zcl_decode for the Zigbee application layer); CoAP is the constrained-IoT " +
		"counterpart that runs on smaller mesh networks.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (IoT application-layer decode space). " +
		"Wrap-vs-native: native — CoAP is a fully public IETF spec (RFC 7252), the walker " +
		"is bit-level decoding over a 4-byte fixed header + variable token + option list + " +
		"optional payload.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded CoAP packet starting from the fixed header byte. ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   coapPacketDecodeHandler,
}

func coapPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("coap_packet_decode: 'hex' is required")
	}
	res, err := coap.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("coap_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
