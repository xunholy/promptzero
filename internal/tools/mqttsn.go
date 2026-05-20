// mqttsn.go — host-side MQTT-SN (MQTT for Sensor Networks)
// message decoder Spec. Wraps the internal/mqttsn walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mqttsn"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mqttsnDecodeSpec)
}

var mqttsnDecodeSpec = Spec{
	Name: "mqtt_sn_decode",
	Description: "Decode an MQTT-SN (MQTT for Sensor Networks) v1.2 message per the " +
		"OASIS MQTT-SN specification. MQTT-SN is the UDP variant of MQTT " +
		"designed for constrained IoT devices (battery-powered sensors, 6LoWPAN " +
		"endpoints, sub-GHz mesh leaves) that cannot afford the overhead of " +
		"MQTT's TCP + CONNECT/CONNACK + TLS stack. Runs over UDP/1883 between a " +
		"sensor and an MQTT-SN Gateway (the gateway translates SN messages back " +
		"into native MQTT for upstream brokers). Interesting to a pentester / " +
		"IoT researcher because (i) many LoRaWAN / Zigbee / 6LoWPAN gateways " +
		"speak MQTT-SN over the IP backhaul — sniffing the uplink reveals " +
		"device telemetry without breaking the sub-GHz crypto; (ii) industrial " +
		"sensor vendors (Bosch, Siemens, ABB) ship MQTT-SN-capable firmware for " +
		"low-power telemetry to a plant-floor gateway; (iii) default-credential " +
		"exposure is common — the CONNECT message ClientId often contains " +
		"hostname + MAC + serial for asset enumeration; (iv) REGISTER / " +
		"PUBLISH messages expose the per-device topic namespace, leaking " +
		"firmware version + sensor metadata. Decodes:\n\n" +
		"- **Variable-length header** (OASIS MQTT-SN v1.2 §5.2.1): 1-byte " +
		"Length (1-255 short form; 0x01 = long-form indicator, then bytes 1-2 " +
		"= uint16 BE length) + 1-byte MsgType.\n" +
		"- **28-entry MsgType name table** (§5.2.3): ADVERTISE / SEARCHGW / " +
		"GWINFO / CONNECT / CONNACK / WILLTOPICREQ / WILLTOPIC / WILLMSGREQ / " +
		"WILLMSG / REGISTER / REGACK / PUBLISH / PUBACK / PUBCOMP / PUBREC / " +
		"PUBREL / SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK / PINGREQ / " +
		"PINGRESP / DISCONNECT / WILLTOPICUPD / WILLTOPICRESP / WILLMSGUPD / " +
		"WILLMSGRESP.\n" +
		"- **Flags byte decode** (CONNECT / PUBLISH / SUBSCRIBE / WILL " +
		"messages): bit 7 DUP / bits 6-5 QoS (00→0, 01→1, 10→2, 11→-1 — MQTT-" +
		"SN-specific fire-and-forget) / bit 4 Retain / bit 3 Will / bit 2 " +
		"CleanSession / bits 1-0 TopicIdType (0 normal / 1 predefined / 2 " +
		"short_name / 3 reserved).\n" +
		"- **Per-MsgType body decoders**: CONNECT (Flags + ProtocolId + " +
		"Duration + ClientId), CONNACK (ReturnCode), WILLTOPIC (Flags + " +
		"TopicName), WILLMSG (Data), REGISTER (TopicId + MsgId + TopicName), " +
		"REGACK (TopicId + MsgId + ReturnCode), PUBLISH (Flags + TopicId + " +
		"MsgId + Data), PUBACK / PUBCOMP / PUBREC / PUBREL (TopicId + MsgId + " +
		"ReturnCode for PUBACK; MsgId only for the others), SUBSCRIBE (Flags + " +
		"MsgId + TopicId or TopicName depending on TopicIdType), SUBACK (Flags " +
		"+ TopicId + MsgId + ReturnCode), UNSUBSCRIBE (Flags + MsgId + Topic), " +
		"UNSUBACK (MsgId), DISCONNECT (optional sleep Duration), ADVERTISE " +
		"(GwId + Duration), GWINFO (GwId + optional GwAdd).\n" +
		"- **4-entry ReturnCode name table** (§5.3.4): 0x00 Accepted / 0x01 " +
		"Rejected_congestion / 0x02 Rejected_invalid_topic_ID / 0x03 " +
		"Rejected_not_supported.\n\n" +
		"Pure offline parser — operators paste MQTT-SN bytes (starting at the " +
		"Length byte, after the UDP-datagram header strip; default UDP port " +
		"1883) and get the documented per-MsgType breakdown.\n\n" +
		"Out of scope (deferred): network framing (feed bytes after the UDP-" +
		"datagram header strip; default UDP port 1883); MQTT-SN over DTLS (v1.3 " +
		"and some v1.2 gateways wrap the protocol in DTLS for transport " +
		"authentication + confidentiality — handle the DTLS strip first); MQTT-" +
		"SN-Gateway state-machine (per-client SubscriptionTable + " +
		"RegisteredTopics state + buffer-during-sleep semantics for low-power " +
		"clients are higher-level analysis); per-Data payload decoding (PUBLISH " +
		"Data bytes are surfaced as raw hex since the per-device telemetry " +
		"encoding — CBOR / MessagePack / Sigfox-RC / vendor binary — is " +
		"dataset-specific); topic-name resolution (the TopicId-to-TopicName " +
		"mapping is established by REGISTER / REGACK pairs at session-start " +
		"time and held in per-client state; surfaces the raw TopicId uint16 " +
		"but does not resolve it without state).\n\n" +
		"Source: docs/catalog/gap-analysis.md (UDP IoT messaging dissector — " +
		"complements the existing mqtt_packet_decode for full MQTT-family " +
		"coverage; targets LoRaWAN / Zigbee / 6LoWPAN gateway backhaul, " +
		"industrial sensor telemetry, and IoT pentest engagements). Wrap-vs-" +
		"native: native — the OASIS MQTT-SN v1.2 specification is publicly " +
		"available and the wire format is tight (1-byte or 3-byte length " +
		"header + 1-byte MsgType + per-MsgType body); no crypto at the parse " +
		"layer.",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"MQTT-SN message bytes starting at the Length byte (after the UDP-datagram header strip; default UDP port 1883). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mqttsnDecodeHandler,
}

func mqttsnDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("mqtt_sn_decode: 'hex' is required")
	}
	res, err := mqttsn.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("mqtt_sn_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
