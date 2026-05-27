// Package cassandra decodes Apache Cassandra CQL binary protocol frames.
// Runs on TCP/9042 (native plaintext default) and TCP/9142 (TLS).
// Compatible with Apache Cassandra, DataStax Enterprise (DSE),
// ScyllaDB, Amazon Keyspaces, Azure Cosmos DB (Cassandra API), Astra DB.
//
// The CQL native binary protocol is the wire format spoken by every
// Cassandra driver (DataStax Java/Python/Go/Node, gocql, pycassa,
// cassandra-rs, etc.). Version 3 (Cassandra 2.1+) through Version 5
// (Cassandra 4.0+ experimental) share a 9-byte fixed frame header;
// the direction bit in the version byte distinguishes requests from
// responses.
//
// Operationally, Cassandra is a **high-value enterprise data-store
// target** — it backs user-profile stores, IoT telemetry ingestion,
// time-series metrics, recommendation engines, and financial ledgers
// at scale. Default open-source Cassandra ships with NO
// authentication (authenticator: AllowAllAuthenticator in
// cassandra.yaml) and NO authorisation (authorizer:
// AllowAllAuthorizer). Many deployments expose TCP/9042 without
// TLS and without credentials. Shodan finds thousands of exposed
// Cassandra nodes.
//
// The wire format leaks:
//
//   - **STARTUP body** — string map containing CQL_VERSION (e.g.
//     "3.0.0") and optional COMPRESSION ("lz4" or "snappy"). The
//     CQL version + protocol version byte together fingerprint the
//     exact Cassandra/ScyllaDB/DSE version in use. The driver name
//     and version may appear in the DRIVER_NAME / DRIVER_VERSION
//     keys of the options string map.
//
//   - **QUERY body** — query text as a UTF-8 long string (4-byte BE
//     length prefix). Contains the full CQL statement including table
//     names, keyspace names, and literal values. A naive CREATE ROLE
//     WITH PASSWORD = '...' or INSERT with hard-coded values leaks
//     credentials or PII in cleartext. The decoder surfaces the first
//     200 characters of query text (truncated for brevity; this is
//     the standard decode pattern matching other decoders in this
//     project).
//
//   - **AUTHENTICATE body** — string containing the authenticator
//     class name (e.g. "org.apache.cassandra.auth.PasswordAuthenticator"
//     or "com.datastax.bdp.cassandra.auth.DseAuthenticator"). This
//     reveals the auth mechanism before any credentials are sent.
//
//   - **AUTH_RESPONSE body** — raw SASL bytes (4-byte BE length +
//     payload). For PasswordAuthenticator the SASL PLAIN payload is
//     "\x00<username>\x00<password>" in cleartext — trivially decoded
//     from a passive packet capture. The decoder surfaces the
//     auth_bytes LENGTH only (privacy-preserving).
//
//   - **ERROR body** — int32 error code + string message. Error codes
//     and messages fingerprint server version, schema state, and
//     operational posture. Error 0x0100 = UNAVAILABLE (reveals RF +
//     consistency); 0x2200 = INVALID_QUERY (reveals schema details in
//     the message); 0x0101 = OVERLOADED; 0x2400 = ALREADY_EXISTS
//     (reveals keyspace/table names).
//
// Wrap-vs-native judgement
//
//	Native. The CQL native binary protocol is publicly documented at
//	github.com/apache/cassandra/blob/trunk/doc/native_protocol_v*.spec.
//	Frame header is 9 bytes (v3+): version(1) + flags(1) + stream(2 BE)
//	+ opcode(1) + body_length(4 BE). No crypto at the parse layer.
//
// What this package covers
//
//   - **Frame header walker**: version byte (direction + protocol
//     version), flags (compression / tracing / custom payload /
//     warning / use_beta), stream ID (multiplexing), opcode, body
//     length.
//
//   - **16-entry opcode name table**: ERROR (0x00) through
//     AUTH_SUCCESS (0x10), covering all documented opcodes.
//
//   - **Frame classification**: is_auth_exchange for AUTHENTICATE /
//     AUTH_RESPONSE / AUTH_CHALLENGE / AUTH_SUCCESS; is_query for
//     QUERY / EXECUTE / BATCH / PREPARE; is_startup for STARTUP.
//
//   - **STARTUP body walker**: CQL_VERSION + COMPRESSION extraction
//     from the string map.
//
//   - **QUERY body walker**: query text extraction (first 200 chars,
//     truncated).
//
//   - **AUTHENTICATE body walker**: authenticator class name.
//
//   - **AUTH_RESPONSE body walker**: auth_bytes length only
//     (privacy-preserving; SASL PLAIN creds never extracted).
//
//   - **ERROR body walker**: error code + error message.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Response body parsing** beyond ERROR and AUTHENTICATE —
//     RESULT body (rows / schema change / set_keyspace / void) and
//     SUPPORTED body have API-specific formats; the decoder focuses on
//     the request path where the operator controls the input.
//   - **Compression** — Cassandra supports lz4 and snappy body
//     compression; the decoder detects the Compression flag but does
//     not decompress bodies.
//   - **TLS handshake** — TCP/9142 TLS; handle TLS strip first.
//   - **AUTH_RESPONSE credential extraction** — SASL bytes LENGTH
//     only; NEVER surfaces actual credentials.
//   - **Tracing UUID** — when the Tracing flag is set in a response,
//     the body is prefixed by a 16-byte UUID; the decoder notes the
//     flag but does not strip the UUID.
//   - **Custom payload** — when the CustomPayload flag is set the
//     body contains an extra bytes map; the decoder notes the flag
//     but does not walk it.
//   - **Warnings list** — when the Warning flag is set a response
//     body is prefixed by a string list; the decoder notes the flag
//     but does not walk it.
//   - **DSE v1/v2 extended opcodes** — DSE-specific opcodes beyond
//     the standard 0x00–0x10 range.
package cassandra

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a Cassandra CQL binary protocol frame.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	// Frame header fields
	Version         int    `json:"version"`
	IsRequest       bool   `json:"is_request"`
	IsResponse      bool   `json:"is_response"`
	ProtocolVersion int    `json:"protocol_version"`
	Flags           int    `json:"flags"`
	FlagCompression bool   `json:"flag_compression"`
	FlagTracing     bool   `json:"flag_tracing"`
	FlagCustomPload bool   `json:"flag_custom_payload"`
	FlagWarning     bool   `json:"flag_warning"`
	FlagUseBeta     bool   `json:"flag_use_beta"`
	StreamID        int    `json:"stream_id"`
	Opcode          int    `json:"opcode"`
	OpcodeName      string `json:"opcode_name"`
	BodyLength      int    `json:"body_length"`

	// Extracted per-opcode fields
	CQLVersion         string `json:"cql_version,omitempty"`
	Compression        string `json:"compression,omitempty"`
	QueryText          string `json:"query_text,omitempty"`
	QueryTruncated     bool   `json:"query_truncated,omitempty"`
	AuthenticatorClass string `json:"authenticator_class,omitempty"`
	AuthBytes          int    `json:"auth_bytes,omitempty"`
	ErrorCode          int    `json:"error_code,omitempty"`
	ErrorMessage       string `json:"error_message,omitempty"`

	// Frame classification
	IsAuthExchange bool `json:"is_auth_exchange"`
	IsQuery        bool `json:"is_query"`
	IsStartup      bool `json:"is_startup"`
}

const frameHeaderSize = 9 // version(1) + flags(1) + stream(2) + opcode(1) + length(4)

const maxQueryPreview = 200

// Decode parses a Cassandra CQL binary protocol frame from a hex string.
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
	if len(b) < frameHeaderSize {
		return nil, fmt.Errorf("cassandra frame truncated (%d bytes; need %d)", len(b), frameHeaderSize)
	}

	r := &Result{TotalBytes: len(b)}

	// version byte: bit7=direction, bits6-0=protocol version
	versionByte := b[0]
	r.Version = int(versionByte)
	r.IsResponse = (versionByte & 0x80) != 0
	r.IsRequest = !r.IsResponse
	r.ProtocolVersion = int(versionByte & 0x7F)

	// flags byte
	flags := b[1]
	r.Flags = int(flags)
	r.FlagCompression = (flags & 0x01) != 0
	r.FlagTracing = (flags & 0x02) != 0
	r.FlagCustomPload = (flags & 0x04) != 0
	r.FlagWarning = (flags & 0x08) != 0
	r.FlagUseBeta = (flags & 0x10) != 0

	// stream ID (2-byte BE signed)
	r.StreamID = int(int16(binary.BigEndian.Uint16(b[2:4])))

	// opcode
	r.Opcode = int(b[4])
	r.OpcodeName = opcodeName(r.Opcode)

	// body length (4-byte BE)
	r.BodyLength = int(binary.BigEndian.Uint32(b[5:9]))

	classifyFrame(r)

	body := b[frameHeaderSize:]
	decodeBody(r, body)

	return r, nil
}

func classifyFrame(r *Result) {
	switch r.Opcode {
	case 0x01: // STARTUP
		r.IsStartup = true
	case 0x07, 0x09, 0x0A, 0x0D: // QUERY, PREPARE, EXECUTE, BATCH
		r.IsQuery = true
	case 0x03, 0x0E, 0x0F, 0x10: // AUTHENTICATE, AUTH_CHALLENGE, AUTH_RESPONSE, AUTH_SUCCESS
		r.IsAuthExchange = true
	}
}

func decodeBody(r *Result, body []byte) {
	switch r.Opcode {
	case 0x01: // STARTUP
		decodeStartup(r, body)
	case 0x07: // QUERY
		decodeQuery(r, body)
	case 0x03: // AUTHENTICATE
		decodeAuthenticate(r, body)
	case 0x0F: // AUTH_RESPONSE
		decodeAuthResponse(r, body)
	case 0x00: // ERROR
		decodeError(r, body)
	}
}

// decodeStartup parses the STARTUP body: a [string map] of options.
// The string map format is: int16 BE count, then count × (string key + string value).
// Strings are: int16 BE length + UTF-8 bytes.
func decodeStartup(r *Result, body []byte) {
	if len(body) < 2 {
		return
	}
	count := int(binary.BigEndian.Uint16(body[0:2]))
	off := 2
	for i := 0; i < count; i++ {
		k, n := readString(body[off:])
		if n == 0 {
			break
		}
		off += n
		v, n := readString(body[off:])
		if n == 0 {
			break
		}
		off += n
		switch strings.ToUpper(k) {
		case "CQL_VERSION":
			r.CQLVersion = v
		case "COMPRESSION":
			r.Compression = v
		}
	}
}

// decodeQuery parses the QUERY body: [long string] + [query parameters].
// The long string is: int32 BE length + UTF-8 bytes.
func decodeQuery(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	qLen := int(binary.BigEndian.Uint32(body[0:4]))
	off := 4
	if qLen < 0 || off+qLen > len(body) {
		// clamp to available bytes
		qLen = len(body) - off
		if qLen < 0 {
			return
		}
	}
	query := string(body[off : off+qLen])
	if len(query) > maxQueryPreview {
		r.QueryText = query[:maxQueryPreview]
		r.QueryTruncated = true
	} else {
		r.QueryText = query
	}
}

// decodeAuthenticate parses the AUTHENTICATE body: a [string] containing
// the authenticator class name.
func decodeAuthenticate(r *Result, body []byte) {
	s, _ := readString(body)
	r.AuthenticatorClass = s
}

// decodeAuthResponse parses the AUTH_RESPONSE body: [bytes] (int32 BE
// length + raw SASL bytes). We surface the length only.
func decodeAuthResponse(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	authLen := int(int32(binary.BigEndian.Uint32(body[0:4])))
	if authLen < 0 {
		authLen = 0 // null bytes value
	}
	r.AuthBytes = authLen
}

// decodeError parses the ERROR body: int32 BE error_code + [string] message.
func decodeError(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	r.ErrorCode = int(binary.BigEndian.Uint32(body[0:4]))
	msg, _ := readString(body[4:])
	r.ErrorMessage = msg
}

// readString reads a CQL protocol short string (int16 BE length prefix + UTF-8).
func readString(b []byte) (string, int) {
	if len(b) < 2 {
		return "", 0
	}
	l := int(binary.BigEndian.Uint16(b[0:2]))
	if l < 0 || 2+l > len(b) {
		return "", 0
	}
	return string(b[2 : 2+l]), 2 + l
}

func opcodeName(op int) string {
	switch op {
	case 0x00:
		return "ERROR"
	case 0x01:
		return "STARTUP"
	case 0x02:
		return "READY"
	case 0x03:
		return "AUTHENTICATE"
	case 0x05:
		return "OPTIONS"
	case 0x06:
		return "SUPPORTED"
	case 0x07:
		return "QUERY"
	case 0x08:
		return "RESULT"
	case 0x09:
		return "PREPARE"
	case 0x0A:
		return "EXECUTE"
	case 0x0B:
		return "REGISTER"
	case 0x0C:
		return "EVENT"
	case 0x0D:
		return "BATCH"
	case 0x0E:
		return "AUTH_CHALLENGE"
	case 0x0F:
		return "AUTH_RESPONSE"
	case 0x10:
		return "AUTH_SUCCESS"
	}
	return fmt.Sprintf("opcode_0x%02x", op)
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
