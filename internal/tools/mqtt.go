// mqtt.go — host-side MQTT v3.1.1 control packet dissector
// Spec, delegating to the internal/mqtt package for the walker
// proper.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mqtt"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mqttPacketDecodeSpec)
}

var mqttPacketDecodeSpec = Spec{
	Name: "mqtt_packet_decode",
	Description: "Decode an MQTT v3.1.1 control packet — the application-layer protocol used " +
		"by most IoT smart-home / industrial-sensor / broker setups. Per OASIS MQTT v3.1.1 " +
		"spec. Decodes:\n\n" +
		"- **Fixed header**: 4-bit packet type (CONNECT / CONNACK / PUBLISH / PUBACK / " +
		"PUBREC / PUBREL / PUBCOMP / SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK / PINGREQ / " +
		"PINGRESP / DISCONNECT) + 4-bit flags + variable-byte-integer remaining length (1-4 " +
		"bytes).\n" +
		"- **CONNECT**: protocol name + version + flags (clean session / will / username / " +
		"password) + keep-alive + client ID + optional will topic/message + optional " +
		"username/password (all strings 2-byte length-prefixed UTF-8).\n" +
		"- **CONNACK**: session-present flag + return code with documented name lookup " +
		"(Accepted / unacceptable protocol version / identifier rejected / server unavailable " +
		"/ bad username or password / not authorized).\n" +
		"- **PUBLISH**: DUP / QoS / RETAIN flags from the fixed header + topic name + " +
		"optional packet ID (QoS > 0) + payload (surfaced as both hex and ASCII string when " +
		"printable).\n" +
		"- **SUBSCRIBE / UNSUBSCRIBE**: packet ID + topic-filter list with per-filter QoS.\n" +
		"- **SUBACK**: packet ID + per-filter return codes.\n" +
		"- **PUBACK / PUBREC / PUBREL / PUBCOMP / UNSUBACK**: packet ID.\n" +
		"- **PINGREQ / PINGRESP / DISCONNECT**: header-only.\n\n" +
		"Pure offline parser — operators paste a captured MQTT packet from Wireshark / " +
		"mosquitto_sub / any MQTT sniffer and inspect every field without re-running the " +
		"capture. Pairs with the existing IoT decoders (zigbee_zcl_decode / nrf24_packet_decode " +
		"/ ble_gap_decode); MQTT is the IP-side application-layer protocol IoT devices speak " +
		"to their brokers.\n\n" +
		"Accepts ':' / '-' / '_' / whitespace separators.\n\n" +
		"Source: docs/catalog/gap-analysis.md (IoT application-layer decode space). " +
		"Wrap-vs-native: native — MQTT v3.1.1 is a fully public OASIS spec, the walker is " +
		"bit-level decoding over a 2-5 byte fixed header + variable header + payload.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Hex-encoded MQTT control packet starting from the fixed header byte. ':' / '-' / '_' / whitespace separators tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mqttPacketDecodeHandler,
}

func mqttPacketDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("mqtt_packet_decode: 'hex' is required")
	}
	res, err := mqtt.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("mqtt_packet_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
