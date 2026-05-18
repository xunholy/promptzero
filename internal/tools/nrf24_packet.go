// nrf24_packet.go — host-side NRF24L01 ESB packet dissector
// Spec, delegating to the internal/nrf24 package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/nrf24"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(nrf24PacketDecodeSpec)
}

var nrf24PacketDecodeSpec = Spec{
	Name: "nrf24_packet_decode",
	Description: "Decode an NRF24L01 Enhanced Shockburst (ESB) packet — the wire format used " +
		"by Nordic NRF24 radios + Logitech Unifying wireless keyboards/mice (Mousejack target " +
		"surface). Decodes:\n\n" +
		"- **Address** (3 / 4 / 5 bytes): the RF address captured from the packet head.\n" +
		"- **Packet Control Field**: 6-bit payload length + 2-bit Packet ID (PID, wraps mod 4) " +
		"+ NO_ACK flag.\n" +
		"- **Payload** (0-32 bytes): surfaced as hex.\n" +
		"- **CRC** (1 or 2 bytes): surfaced as hex; validation against the computed CRC is " +
		"left to the operator's deframer.\n" +
		"- **Logitech Unifying / Mousejack recognition**: when the payload starts with a " +
		"device-index byte + a known Logitech report-type byte (0x40 HID Boot Keyboard / " +
		"0x4D Mouse / 0x4F Encrypted Keyboard / 0x50 HID++ short / 0x51 HID++ long / 0xC1 " +
		"Keepalive / 0xC2 Plaintext Keyboard / 0xD3 Pairing / 0xDF Pairing notification), the " +
		"decoder surfaces a structured Logitech view with device index + report type + body.\n\n" +
		"Pure offline parser — no Flipper / Crazyradio required. Pairs with the existing " +
		"nrf24_sniff_start / nrf24_list_targets / nrf24_mousejack_start / nrf24_payload_build " +
		"Specs (those drive the radio; this is the host-side analyst entry point for captured " +
		"packets). Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (NRF24 / Mousejack decode space). Wrap-vs-native: " +
		"native — NRF24L01 ESB is a public Nordic data-sheet spec, Logitech Unifying is a " +
		"reverse-engineered public format (Bastille's Mousejack research).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded NRF24 ESB packet body (address + PCF + payload + CRC, as deframed by your sniffer)."},
			"address_length":{"type":"integer","description":"Address byte count (3 / 4 / 5). Default 5 — the NRF24L01 power-on default and the Logitech Unifying default."},
			"crc_length":{"type":"integer","description":"CRC byte count (1 / 2). Default 2 — the most common Unifying configuration."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   nrf24PacketDecodeHandler,
}

func nrf24PacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("nrf24_packet_decode: 'hex' is required")
	}
	opts := nrf24.DecodeOptions{}
	if v, ok := p["address_length"]; ok {
		switch x := v.(type) {
		case float64:
			opts.AddressLength = int(x)
		case int:
			opts.AddressLength = x
		}
	}
	if v, ok := p["crc_length"]; ok {
		switch x := v.(type) {
		case float64:
			opts.CRCLength = int(x)
		case int:
			opts.CRCLength = x
		}
	}
	res, err := nrf24.Decode(raw, opts)
	if err != nil {
		return "", fmt.Errorf("nrf24_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
