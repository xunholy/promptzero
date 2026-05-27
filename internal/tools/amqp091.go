// amqp091.go — host-side AMQP 0-9-1 wire-protocol decoder Spec.
// Wraps the internal/amqp091 walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/amqp091"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(amqp091DecodeSpec)
}

var amqp091DecodeSpec = Spec{
	Name: "amqp091_decode",
	Description: "Decode an AMQP 0-9-1 wire-protocol frame or protocol header " +
		"per the AMQP 0-9-1 specification. TCP/5672 (plaintext) and " +
		"TCP/5671 (AMQPS — TLS-wrapped). Canonical implementation is " +
		"RabbitMQ; also LavinMQ, Apache Qpid, Azure Service Bus (compat " +
		"mode), VMware Tanzu RabbitMQ, CloudAMQP (hosted). High-value " +
		"enterprise messaging target — brokers inter-service comms in " +
		"microservice architectures, event-driven systems, async job " +
		"queues. Default RabbitMQ ships with 'guest/guest' localhost-only " +
		"but many deployments expose TCP/5672 with weak credentials.\n\n" +
		"The wire format leaks: **Server product + version + platform " +
		"via Connection.Start** (server-properties table: product=" +
		"'RabbitMQ', version='3.13.0', platform='Erlang/OTP 26.2.1', " +
		"cluster_name; mechanisms list: PLAIN cleartext default / " +
		"AMQPLAIN legacy / EXTERNAL client-cert / RABBIT-CR-DEMO — " +
		"canonical version fingerprint for CVE selection); **cleartext " +
		"credentials via Connection.StartOk with PLAIN** (SASL PLAIN " +
		"= \\0<username>\\0<password> in cleartext — decoder surfaces " +
		"mechanism + response_bytes LENGTH only, privacy-preserving, " +
		"but flags the cleartext exposure); **virtual-host disclosure " +
		"via Connection.Open** (vhost name reveals environment topology " +
		"e.g. '/' default, 'production', 'staging'); **exchange + " +
		"routing-key disclosure via Basic.Publish** (message routing " +
		"topology); **queue name disclosure via Queue.Declare / " +
		"Queue.Bind / Basic.Consume**; **connection tuning via " +
		"Connection.Tune/TuneOk** (channel-max, frame-max, heartbeat " +
		"— reveals broker config, informs resource exhaustion attacks).\n\n" +
		"Decodes:\n\n" +
		"- **Protocol header detection**: 'AMQP\\x00\\x00\\x09\\x01' " +
		"magic (client-sent protocol negotiation).\n" +
		"- **7-byte frame header walker**: type (Method=1 / Content " +
		"Header=2 / Content Body=3 / Heartbeat=4) / channel (2 BE) / " +
		"size (4 BE).\n" +
		"- **Frame-end 0xCE validation**.\n" +
		"- **Method frame class+method decoder**: 7 classes — " +
		"Connection (10) / Channel (20) / Exchange (40) / Queue (50) " +
		"/ Basic (60) / Confirm (85) / Tx (90). Full method name " +
		"table.\n" +
		"- **Connection.Start walker**: version-major + version-minor " +
		"+ server-properties table (product/version/platform/" +
		"cluster_name) + mechanisms long-string + locales.\n" +
		"- **Connection.StartOk walker**: client-properties + mechanism " +
		"+ response length (privacy-preserving) + locale. Flags PLAIN " +
		"cleartext exposure.\n" +
		"- **Connection.Tune/TuneOk walker**: channel-max + frame-max " +
		"+ heartbeat.\n" +
		"- **Connection.Open walker**: virtual-host.\n" +
		"- **Connection.Close walker**: reply-code + reply-text + " +
		"failing class/method.\n" +
		"- **Exchange.Declare walker**: exchange name + type.\n" +
		"- **Queue.Declare walker**: queue name.\n" +
		"- **Queue.Bind walker**: queue + exchange + routing-key.\n" +
		"- **Basic.Publish walker**: exchange + routing-key.\n" +
		"- **Basic.Consume walker**: queue name.\n" +
		"- **Basic.Deliver walker**: exchange + routing-key.\n" +
		"- **AMQP table walker**: 4-byte BE length + field entries " +
		"(short-string key + type tag + value). Supports string 'S', " +
		"long-int 'I', boolean 't', nested table 'F'.\n\n" +
		"Pure offline parser — paste AMQP bytes (TCP-segment payload " +
		"hex; default TCP/5672 plaintext, TCP/5671 AMQPS) from tcpdump " +
		"/ Wireshark AMQP dissector and get per-frame breakdown.\n\n" +
		"Out of scope: content header property parsing (content-type, " +
		"delivery-mode, headers property-flags bitfield — identified " +
		"but not walked); content body reassembly (raw payload, " +
		"identified by frame type + size); AMQP 1.0 (completely " +
		"different wire protocol, ISO/IEC 19464, not binary-compatible " +
		"with 0-9-1); TLS handshake (AMQPS TCP/5671 — strip TLS " +
		"first); RabbitMQ management HTTP API (TCP/15672); RabbitMQ " +
		"Streams protocol (TCP/5552); STOMP / MQTT plugin protocols; " +
		"credential extraction (response_bytes LENGTH only — NEVER " +
		"surfaces actual username/password values).\n\n" +
		"Source: gap analysis (enterprise messaging backbone — " +
		"canonical RabbitMQ / AMQP 0-9-1 pentest dissector for " +
		"Connection.Start version fingerprint + SASL PLAIN cleartext " +
		"credential exposure + vhost/exchange/queue topology " +
		"disclosure; pairs with kafka_decode for the enterprise " +
		"messaging surface). Wrap-vs-native: native — AMQP 0-9-1 " +
		"spec is publicly available; fixed 7-byte frame header; " +
		"method frames carry classId + methodId + typed arguments; " +
		"table format is a length-prefixed field walker; no crypto " +
		"at the parse layer; SASL payload NEVER decoded (length only " +
		"— privacy-preserving while flagging cleartext exposure).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"AMQP 0-9-1 frame bytes as hex (the TCP-segment payload; default TCP/5672 plaintext, TCP/5671 AMQPS). Includes the protocol header ('AMQP\\x00\\x00\\x09\\x01') or a frame (7-byte header + payload + 0xCE frame-end). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   amqp091DecodeHandler,
}

func amqp091DecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("amqp091_decode: 'hex' is required")
	}
	res, err := amqp091.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("amqp091_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
