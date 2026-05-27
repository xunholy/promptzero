// Package kafka decodes Apache Kafka wire-protocol request/response
// messages per the Kafka protocol specification (KIP-35 and the
// protocol guide). Runs on TCP/9092 (plaintext default), TCP/9093
// (SSL/TLS), TCP/9094 (SASL_PLAINTEXT), TCP/9095 (SASL_SSL).
// Compatible with Apache Kafka, Confluent Platform, Amazon MSK,
// Azure Event Hubs (Kafka-compatible endpoint), Redpanda, Strimzi
// (Kubernetes operator), and WarpStream.
//
// Operationally, Kafka is a **high-value enterprise streaming
// target** — it brokers event streams, log aggregation, CDC
// pipelines, and inter-service messaging at massive scale.
// Default Apache Kafka ships with NO authentication (PLAINTEXT
// listener) and no authorization (allow.everyone.if.no.acl.found
// = true in older versions). Many deployments expose TCP/9092
// without SASL, and even SASL_PLAINTEXT transmits credentials in
// cleartext. Shodan finds thousands of exposed Kafka brokers.
//
// The wire format leaks:
//
//   - **API version negotiation via ApiVersions (API key 18)**
//     — every client sends an ApiVersions request as the first
//     message to discover supported API keys and version ranges.
//     The response reveals the full set of supported API keys +
//     min/max versions, which fingerprints the exact Kafka broker
//     version (each release adds/extends API versions in a known
//     sequence). Also surfaces `client_software_name` and
//     `client_software_version` in v3+ flexible headers.
//
//   - **Broker cluster metadata via Metadata (API key 3)** —
//     response includes broker IDs + host:port pairs (full
//     cluster topology disclosure), topic names + partition
//     counts + leader/ISR assignments, cluster ID, controller
//     broker ID. Canonical pre-attack recon — reveals internal
//     hostnames and network topology.
//
//   - **SASL authentication via SaslHandshake (API key 17) +
//     SaslAuthenticate (API key 36)** — SaslHandshake response
//     lists enabled_mechanisms (PLAIN / SCRAM-SHA-256 /
//     SCRAM-SHA-512 / GSSAPI / OAUTHBEARER). SaslAuthenticate
//     carries the SASL auth bytes. SASL PLAIN = cleartext
//     \0<username>\0<password>. The decoder surfaces mechanism +
//     auth_bytes LENGTH only (privacy-preserving).
//
//   - **Topic + consumer group disclosure** — Produce (0),
//     Fetch (1), ListOffsets (2), OffsetCommit (8),
//     OffsetFetch (9), FindCoordinator (10), JoinGroup (11),
//     SyncGroup (14), ListGroups (16), DescribeGroups (15),
//     CreateTopics (19), DeleteTopics (20) — all surface topic
//     and/or group names in cleartext.
//
//   - **ACL manipulation via CreateAcls (30) / DeleteAcls (31)
//     / DescribeAcls (29)** — access control operations.
//
// Wrap-vs-native judgement
//
//	Native. The Kafka protocol is publicly documented in the
//	Apache Kafka protocol guide. Requests and responses share
//	a common header format: 4-byte BE message size + 2-byte BE
//	API key + 2-byte BE API version + 4-byte BE correlation ID
//	+ nullable string client ID (requests) or correlation ID
//	(responses). No crypto at the parse layer.
//
// What this package covers
//
//   - **Request header walker**: message_size (4 BE) + api_key
//     (2 BE) + api_version (2 BE) + correlation_id (4 BE) +
//     client_id (nullable string — 2-byte BE length, -1 = null).
//
//   - **39-entry API key name table** (per Kafka 3.7): Produce
//     (0) through AlterUserScramCredentials (51), covering all
//     commonly encountered request types.
//
//   - **Request type classification**: version_probe for
//     ApiVersions (18); metadata_request for Metadata (3);
//     sasl_handshake for SaslHandshake (17); sasl_auth for
//     SaslAuthenticate (36); topic_admin for CreateTopics (19) /
//     DeleteTopics (20); acl_operation for CreateAcls (30) /
//     DeleteAcls (31) / DescribeAcls (29).
//
//   - **Metadata request walker**: topic count + first topic
//     name extraction.
//
//   - **Produce request walker**: transactional_id (nullable
//     string) + acks + timeout + first topic name.
//
//   - **SaslHandshake request walker**: mechanism name.
//
//   - **SaslAuthenticate request walker**: auth_bytes length
//     only (privacy-preserving).
//
//   - **FindCoordinator walker**: coordinator_key (group name).
//
//   - **JoinGroup walker**: group_id + protocol_type.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Response parsing** — responses share correlation_id but
//     have API-specific body formats. The decoder focuses on
//     requests where the operator controls the input.
//   - **Flexible header (KIP-482) tagged fields** — Kafka 2.4+
//     added tagged fields to v2+ headers; the decoder reads the
//     fixed header but does not walk tagged field sections.
//   - **Record batch / message set parsing** — Produce/Fetch
//     carry compressed record batches (magic byte 2); the
//     decoder extracts topic names but not individual records.
//   - **TLS handshake** — SSL/SASL_SSL listeners on TCP/9093
//     and TCP/9095; handle TLS strip first.
//   - **Kafka Connect / Schema Registry / ksqlDB** — separate
//     HTTP-based APIs, not the binary wire protocol.
//   - **Credential extraction** — auth_bytes LENGTH only for
//     SASL; NEVER surfaces actual credentials.
package kafka

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a Kafka wire-protocol request.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	MessageSize   int    `json:"message_size"`
	APIKey        int    `json:"api_key"`
	APIKeyName    string `json:"api_key_name"`
	APIVersion    int    `json:"api_version"`
	CorrelationID int    `json:"correlation_id"`
	ClientID      string `json:"client_id,omitempty"`

	// Request classification
	IsVersionProbe   bool `json:"is_version_probe"`
	IsMetadataReq    bool `json:"is_metadata_request"`
	IsSASLHandshake  bool `json:"is_sasl_handshake"`
	IsSASLAuth       bool `json:"is_sasl_auth"`
	IsTopicAdmin     bool `json:"is_topic_admin"`
	IsACLOperation   bool `json:"is_acl_operation"`
	IsGroupOperation bool `json:"is_group_operation"`

	// Extracted fields
	TopicName       string `json:"topic_name,omitempty"`
	TopicCount      int    `json:"topic_count,omitempty"`
	GroupID         string `json:"group_id,omitempty"`
	SASLMechanism   string `json:"sasl_mechanism,omitempty"`
	AuthBytes       int    `json:"auth_bytes,omitempty"`
	Acks            int    `json:"acks,omitempty"`
	TimeoutMs       int    `json:"timeout_ms,omitempty"`
	TransactionalID string `json:"transactional_id,omitempty"`
	ProtocolType    string `json:"protocol_type,omitempty"`
	CoordinatorKey  string `json:"coordinator_key,omitempty"`

	// Security flags
	IsCleartextSASL   bool   `json:"is_cleartext_sasl"`
	CleartextSASLFlag string `json:"cleartext_sasl_flag,omitempty"`
}

const requestHeaderSize = 12 // api_key(2) + api_version(2) + correlation_id(4) + message_size prefix(4)

// Decode parses a Kafka wire-protocol request from a hex string.
func Decode(hexStr string) (*Result, error) {
	clean := stripSeparators(hexStr)
	if len(clean) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex (%d nibbles)", len(clean))
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) < requestHeaderSize {
		return nil, fmt.Errorf("kafka header truncated (%d bytes; need %d)", len(b), requestHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}
	r.MessageSize = int(binary.BigEndian.Uint32(b[0:4]))
	r.APIKey = int(binary.BigEndian.Uint16(b[4:6]))
	r.APIVersion = int(binary.BigEndian.Uint16(b[6:8]))
	r.CorrelationID = int(binary.BigEndian.Uint32(b[8:12]))
	r.APIKeyName = apiKeyName(r.APIKey)

	off := 12
	// client_id — nullable string (int16 BE length, -1 = null)
	if off+2 <= len(b) {
		clientIDLen := int(int16(binary.BigEndian.Uint16(b[off : off+2])))
		off += 2
		if clientIDLen > 0 && off+clientIDLen <= len(b) {
			r.ClientID = string(b[off : off+clientIDLen])
			off += clientIDLen
		}
	}

	classifyRequest(r)

	body := b[off:]
	decodeRequestBody(r, body)

	return r, nil
}

func classifyRequest(r *Result) {
	switch r.APIKey {
	case 18:
		r.IsVersionProbe = true
	case 3:
		r.IsMetadataReq = true
	case 17:
		r.IsSASLHandshake = true
	case 36:
		r.IsSASLAuth = true
	case 19, 20:
		r.IsTopicAdmin = true
	case 29, 30, 31:
		r.IsACLOperation = true
	case 10, 11, 14, 15, 16:
		r.IsGroupOperation = true
	}
}

func decodeRequestBody(r *Result, body []byte) {
	switch r.APIKey {
	case 0:
		decodeProduceRequest(r, body)
	case 3:
		decodeMetadataRequest(r, body)
	case 10:
		decodeFindCoordinatorRequest(r, body)
	case 11:
		decodeJoinGroupRequest(r, body)
	case 17:
		decodeSASLHandshakeRequest(r, body)
	case 36:
		decodeSASLAuthenticateRequest(r, body)
	}
}

func decodeProduceRequest(r *Result, body []byte) {
	off := 0
	// transactional_id (nullable string) — v3+
	if r.APIVersion >= 3 && off+2 <= len(body) {
		tid, n := readNullableString(body[off:])
		r.TransactionalID = tid
		off += n
	}

	// acks (int16)
	if off+2 > len(body) {
		return
	}
	r.Acks = int(int16(binary.BigEndian.Uint16(body[off : off+2])))
	off += 2

	// timeout (int32)
	if off+4 > len(body) {
		return
	}
	r.TimeoutMs = int(binary.BigEndian.Uint32(body[off : off+4]))
	off += 4

	// topic_count (int32) + first topic name
	if off+4 > len(body) {
		return
	}
	r.TopicCount = int(binary.BigEndian.Uint32(body[off : off+4]))
	off += 4
	if r.TopicCount > 0 && off+2 <= len(body) {
		topic, _ := readString(body[off:])
		r.TopicName = topic
	}
}

func decodeMetadataRequest(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	r.TopicCount = int(binary.BigEndian.Uint32(body[0:4]))
	off := 4
	if r.TopicCount > 0 && off+2 <= len(body) {
		topic, _ := readString(body[off:])
		r.TopicName = topic
	}
}

func decodeFindCoordinatorRequest(r *Result, body []byte) {
	if len(body) < 2 {
		return
	}
	key, _ := readString(body)
	r.CoordinatorKey = key
	r.GroupID = key
}

func decodeJoinGroupRequest(r *Result, body []byte) {
	if len(body) < 2 {
		return
	}
	off := 0
	gid, n := readString(body[off:])
	r.GroupID = gid
	off += n

	// session_timeout (int32)
	off += 4
	// rebalance_timeout (int32) — v1+
	if r.APIVersion >= 1 {
		off += 4
	}
	// member_id (string)
	_, n = readString(body[off:])
	off += n
	// protocol_type (string)
	if off+2 <= len(body) {
		pt, _ := readString(body[off:])
		r.ProtocolType = pt
	}
}

func decodeSASLHandshakeRequest(r *Result, body []byte) {
	if len(body) < 2 {
		return
	}
	mech, _ := readString(body)
	r.SASLMechanism = mech

	if mech == "PLAIN" {
		r.IsCleartextSASL = true
		r.CleartextSASLFlag = "SASL PLAIN — credentials transmitted as \\0<username>\\0<password> in cleartext on SASL_PLAINTEXT listener (TCP/9094); offline capture yields immediate credential access"
	}
}

func decodeSASLAuthenticateRequest(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	authLen := int(binary.BigEndian.Uint32(body[0:4]))
	r.AuthBytes = authLen
}

// readString reads a Kafka string (int16 BE length prefix).
func readString(b []byte) (string, int) {
	if len(b) < 2 {
		return "", 0
	}
	l := int(int16(binary.BigEndian.Uint16(b[0:2])))
	if l < 0 {
		return "", 2
	}
	if 2+l > len(b) {
		return "", 2
	}
	return string(b[2 : 2+l]), 2 + l
}

// readNullableString reads a Kafka nullable string (-1 = null).
func readNullableString(b []byte) (string, int) {
	if len(b) < 2 {
		return "", 0
	}
	l := int(int16(binary.BigEndian.Uint16(b[0:2])))
	if l < 0 {
		return "", 2
	}
	if 2+l > len(b) {
		return "", 2
	}
	return string(b[2 : 2+l]), 2 + l
}

func apiKeyName(k int) string {
	switch k {
	case 0:
		return "Produce"
	case 1:
		return "Fetch"
	case 2:
		return "ListOffsets"
	case 3:
		return "Metadata"
	case 4:
		return "LeaderAndIsr"
	case 5:
		return "StopReplica"
	case 6:
		return "UpdateMetadata"
	case 7:
		return "ControlledShutdown"
	case 8:
		return "OffsetCommit"
	case 9:
		return "OffsetFetch"
	case 10:
		return "FindCoordinator"
	case 11:
		return "JoinGroup"
	case 12:
		return "Heartbeat"
	case 13:
		return "LeaveGroup"
	case 14:
		return "SyncGroup"
	case 15:
		return "DescribeGroups"
	case 16:
		return "ListGroups"
	case 17:
		return "SaslHandshake"
	case 18:
		return "ApiVersions"
	case 19:
		return "CreateTopics"
	case 20:
		return "DeleteTopics"
	case 21:
		return "DeleteRecords"
	case 22:
		return "InitProducerId"
	case 23:
		return "OffsetForLeaderEpoch"
	case 24:
		return "AddPartitionsToTxn"
	case 25:
		return "AddOffsetsToTxn"
	case 26:
		return "EndTxn"
	case 27:
		return "WriteTxnMarkers"
	case 28:
		return "TxnOffsetCommit"
	case 29:
		return "DescribeAcls"
	case 30:
		return "CreateAcls"
	case 31:
		return "DeleteAcls"
	case 32:
		return "DescribeConfigs"
	case 33:
		return "AlterConfigs"
	case 34:
		return "AlterReplicaLogDirs"
	case 35:
		return "DescribeLogDirs"
	case 36:
		return "SaslAuthenticate"
	case 37:
		return "CreatePartitions"
	case 38:
		return "CreateDelegationToken"
	case 39:
		return "RenewDelegationToken"
	case 40:
		return "ExpireDelegationToken"
	case 41:
		return "DescribeDelegationToken"
	case 42:
		return "DeleteGroups"
	case 43:
		return "ElectLeaders"
	case 44:
		return "IncrementalAlterConfigs"
	case 45:
		return "AlterPartitionReassignments"
	case 46:
		return "ListPartitionReassignments"
	case 47:
		return "OffsetDelete"
	case 48:
		return "DescribeClientQuotas"
	case 49:
		return "AlterClientQuotas"
	case 50:
		return "DescribeUserScramCredentials"
	case 51:
		return "AlterUserScramCredentials"
	}
	return fmt.Sprintf("api_key_%d", k)
}

func stripSeparators(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		s = s[2:]
	}
	var sb strings.Builder
	sb.Grow(len(s))
	for _, r := range s {
		switch r {
		case ' ', '\t', '\n', '\r', ':', '-', '_':
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
