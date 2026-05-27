// cassandra.go — host-side Cassandra CQL binary protocol decoder Spec.
// Wraps the internal/cassandra walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/cassandra"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(cassandraDecodeSpec)
}

var cassandraDecodeSpec = Spec{
	Name: "cassandra_decode",
	Description: "Decode an Apache Cassandra CQL native binary protocol frame. " +
		"TCP/9042 (plaintext default), TCP/9142 (TLS). Compatible with " +
		"Apache Cassandra, DataStax Enterprise (DSE), ScyllaDB, Amazon " +
		"Keyspaces, Azure Cosmos DB (Cassandra API), Astra DB. High-value " +
		"enterprise data-store target — backs user-profile stores, IoT " +
		"telemetry, time-series metrics, recommendation engines, and " +
		"financial ledgers at scale. Default open-source Cassandra ships " +
		"with NO authentication (AllowAllAuthenticator) and NO " +
		"authorisation (AllowAllAuthorizer); many deployments expose " +
		"TCP/9042 unauthenticated. Shodan finds thousands of exposed " +
		"Cassandra nodes.\n\n" +
		"The wire format leaks: **STARTUP body** — string map containing " +
		"CQL_VERSION + optional COMPRESSION (lz4/snappy); CQL version + " +
		"protocol version byte together fingerprint the exact Cassandra / " +
		"ScyllaDB / DSE version; **QUERY body** — full CQL statement as " +
		"UTF-8 cleartext (table names, keyspace names, literal values; a " +
		"CREATE ROLE WITH PASSWORD or INSERT with hard-coded values leaks " +
		"credentials / PII; decoder surfaces first 200 chars, truncated); " +
		"**AUTHENTICATE body** — authenticator class name (reveals auth " +
		"mechanism before any credentials are sent; e.g. " +
		"org.apache.cassandra.auth.PasswordAuthenticator signals cleartext " +
		"SASL PLAIN creds incoming); **AUTH_RESPONSE body** — raw SASL " +
		"bytes (PasswordAuthenticator SASL PLAIN payload is " +
		"\\x00<username>\\x00<password> in cleartext — trivially decoded " +
		"from passive capture; decoder surfaces auth_bytes LENGTH only, " +
		"privacy-preserving); **ERROR body** — error code + message " +
		"(fingerprints server version, schema state, operational posture; " +
		"e.g. 0x2200 INVALID_QUERY reveals schema details in message).\n\n" +
		"Decodes:\n\n" +
		"- **Frame header walker**: version byte (direction bit + protocol " +
		"version), flags (compression / tracing / custom_payload / " +
		"warning / use_beta), stream ID (multiplexing), opcode, body " +
		"length. 9-byte fixed header for CQL v3+.\n" +
		"- **16-entry opcode name table**: ERROR (0x00) through " +
		"AUTH_SUCCESS (0x10).\n" +
		"- **Frame classification**: is_startup (STARTUP 0x01); is_query " +
		"(QUERY 0x07 / PREPARE 0x09 / EXECUTE 0x0A / BATCH 0x0D); " +
		"is_auth_exchange (AUTHENTICATE 0x03 / AUTH_CHALLENGE 0x0E / " +
		"AUTH_RESPONSE 0x0F / AUTH_SUCCESS 0x10).\n" +
		"- **STARTUP walker**: CQL_VERSION + COMPRESSION from string map.\n" +
		"- **QUERY walker**: query text (first 200 chars, truncated).\n" +
		"- **AUTHENTICATE walker**: authenticator class name.\n" +
		"- **AUTH_RESPONSE walker**: auth_bytes length only " +
		"(privacy-preserving — SASL PLAIN creds NEVER extracted).\n" +
		"- **ERROR walker**: error code + error message.\n\n" +
		"Pure offline parser — paste Cassandra bytes (TCP-segment payload " +
		"hex; default TCP/9042) from tcpdump / Wireshark Cassandra " +
		"dissector and get per-frame breakdown.\n\n" +
		"Out of scope: RESULT / SUPPORTED response body parsing; " +
		"lz4/snappy body decompression; TLS handshake (TCP/9142); " +
		"auth_bytes content (length only — NEVER surfaces actual " +
		"credentials); tracing UUID strip; custom payload walk; " +
		"DSE extended opcodes.\n\n" +
		"Source: gap analysis (enterprise NoSQL backbone — canonical " +
		"Cassandra pentest dissector for CQL version fingerprint + " +
		"auth-mechanism enumeration + SASL cleartext credential exposure " +
		"+ query-text keyspace/table topology disclosure; pairs with " +
		"mongodb_decode + redis_decode for the enterprise data-store " +
		"pentest surface). Wrap-vs-native: native — CQL native binary " +
		"protocol is publicly documented; 9-byte fixed header with BE " +
		"integers + short/long strings; no crypto at the parse layer; " +
		"AUTH_RESPONSE payload NEVER decoded (length only).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"Cassandra CQL binary protocol frame bytes as hex (the TCP-segment payload; default TCP/9042 plaintext, TCP/9142 TLS). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   cassandraDecodeHandler,
}

func cassandraDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("cassandra_decode: 'hex' is required")
	}
	res, err := cassandra.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("cassandra_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
