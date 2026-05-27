// kafka.go — host-side Apache Kafka wire-protocol decoder Spec.
// Wraps the internal/kafka walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/kafka"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(kafkaDecodeSpec)
}

var kafkaDecodeSpec = Spec{
	Name: "kafka_decode",
	Description: "Decode an Apache Kafka wire-protocol request per the Kafka " +
		"protocol specification. TCP/9092 (plaintext default), TCP/9093 " +
		"(SSL/TLS), TCP/9094 (SASL_PLAINTEXT), TCP/9095 (SASL_SSL). " +
		"Compatible with Apache Kafka, Confluent Platform, Amazon MSK, " +
		"Azure Event Hubs (Kafka endpoint), Redpanda, Strimzi, " +
		"WarpStream. High-value enterprise streaming target — brokers " +
		"event streams, log aggregation, CDC pipelines, inter-service " +
		"messaging at massive scale. Default Apache Kafka ships with " +
		"NO authentication (PLAINTEXT listener) and no authorization; " +
		"many deployments expose TCP/9092 unauthenticated. Shodan " +
		"finds thousands of exposed Kafka brokers.\n\n" +
		"The wire format leaks: **API version negotiation via " +
		"ApiVersions (key 18)** — every client sends this first; " +
		"response reveals supported API keys + version ranges that " +
		"fingerprint exact broker version; also surfaces " +
		"client_software_name/version in v3+ flexible headers; " +
		"**broker cluster metadata via Metadata (key 3)** — response " +
		"includes broker IDs + host:port pairs (full cluster topology " +
		"disclosure), topic names + partition counts + leader/ISR, " +
		"cluster ID, controller broker ID — canonical pre-attack " +
		"recon; **SASL authentication via SaslHandshake (17) + " +
		"SaslAuthenticate (36)** — SaslHandshake lists " +
		"enabled_mechanisms (PLAIN / SCRAM-SHA-256 / SCRAM-SHA-512 / " +
		"GSSAPI / OAUTHBEARER); SASL PLAIN = cleartext " +
		"\\0<username>\\0<password> on SASL_PLAINTEXT listener " +
		"(TCP/9094); decoder surfaces mechanism + auth_bytes LENGTH " +
		"only (privacy-preserving); **topic + consumer group " +
		"disclosure** — Produce/Fetch/ListOffsets/OffsetCommit/" +
		"JoinGroup/FindCoordinator surface topic and group names " +
		"in cleartext; **ACL manipulation via CreateAcls (30) / " +
		"DeleteAcls (31) / DescribeAcls (29)**.\n\n" +
		"Decodes:\n\n" +
		"- **Request header walker**: message_size (4 BE) + api_key " +
		"(2 BE) + api_version (2 BE) + correlation_id (4 BE) + " +
		"client_id (nullable string).\n" +
		"- **52-entry API key name table** (Kafka 3.7): Produce (0) " +
		"through AlterUserScramCredentials (51).\n" +
		"- **Request classification**: version_probe (ApiVersions 18) " +
		"/ metadata_request (Metadata 3) / sasl_handshake " +
		"(SaslHandshake 17) / sasl_auth (SaslAuthenticate 36) / " +
		"topic_admin (CreateTopics 19 / DeleteTopics 20) / " +
		"acl_operation (29/30/31) / group_operation (10/11/14/15/16).\n" +
		"- **Metadata request walker**: topic count + first topic " +
		"name.\n" +
		"- **Produce request walker**: transactional_id + acks + " +
		"timeout + first topic name.\n" +
		"- **SaslHandshake walker**: mechanism name (PLAIN flagged " +
		"as cleartext exposure).\n" +
		"- **SaslAuthenticate walker**: auth_bytes length only " +
		"(privacy-preserving).\n" +
		"- **FindCoordinator walker**: coordinator_key (group name).\n" +
		"- **JoinGroup walker**: group_id + protocol_type.\n\n" +
		"Pure offline parser — paste Kafka bytes (TCP-segment payload " +
		"hex; default TCP/9092) from tcpdump / Wireshark Kafka " +
		"dissector and get per-request breakdown.\n\n" +
		"Out of scope: response parsing (API-specific body formats); " +
		"flexible header tagged fields (KIP-482, Kafka 2.4+); record " +
		"batch / message set parsing (compressed record batches); " +
		"TLS handshake (SSL/SASL_SSL listeners); Kafka Connect / " +
		"Schema Registry / ksqlDB (separate HTTP APIs); credential " +
		"extraction (auth_bytes LENGTH only — NEVER surfaces actual " +
		"credentials).\n\n" +
		"Source: gap analysis (enterprise streaming backbone — " +
		"canonical Kafka pentest dissector for ApiVersions version " +
		"fingerprint + SaslHandshake mechanism enumeration + SASL " +
		"PLAIN cleartext credential exposure + topic/group topology " +
		"disclosure; pairs with amqp091_decode for the enterprise " +
		"messaging surface). Wrap-vs-native: native — Kafka protocol " +
		"is publicly documented; fixed header format with BE integers " +
		"+ nullable strings; no crypto at the parse layer; SASL " +
		"payload NEVER decoded (length only).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Kafka wire-protocol request bytes as hex (the TCP-segment payload; default TCP/9092 plaintext, TCP/9093 SSL, TCP/9094 SASL_PLAINTEXT, TCP/9095 SASL_SSL). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   kafkaDecodeHandler,
}

func kafkaDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("kafka_decode: 'hex' is required")
	}
	res, err := kafka.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("kafka_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
