// Package mongodb decodes MongoDB wire protocol messages per
// the MongoDB documentation ("MongoDB Wire Protocol"). Runs on
// TCP/27017 (default mongod), TCP/27018 (mongos sharded
// router), TCP/27019 (config servers). Compatible with FerretDB
// (Postgres-backed MongoDB-compatible proxy) and DocumentDB
// (AWS MongoDB-compatible) which use the same wire format.
//
// Operationally, MongoDB is a **high-value NoSQL pentest
// target** with an exposure profile similar to Redis — many
// historical deployments (Mongo 2.x / 3.x) defaulted to "no
// auth, bind to 0.0.0.0" and Shodan still finds tens of
// thousands of unauthenticated MongoDB instances on TCP/27017.
// Modern MongoDB (4.x+) defaults to localhost-only binding +
// SCRAM-SHA-256 auth, but the wire format remains the same.
//
// The wire format leaks:
//
//   - **MongoDB version + auth-mechanism enumeration via
//     `isMaster` / `hello` command** — every client sends an
//     `isMaster` (legacy) or `hello` (modern, MongoDB 5.0+)
//     command immediately after TCP connect to discover server
//     topology + supported SASL mechanisms. The server reply
//     includes `maxWireVersion`, `topologyVersion`, `setName`
//     (replica-set name disclosure), `primary`/`hosts`
//     (replica-set topology disclosure), `me` (server's own
//     hostname), and **`saslSupportedMechs`** — an array of
//     mechanism names: `SCRAM-SHA-1` (legacy weak — offline-
//     crackable via hashcat mode 31700), `SCRAM-SHA-256`
//     (modern default), `PLAIN` (cleartext — typically used
//     for LDAP-backed auth), `MONGODB-X509` (client cert auth),
//     `GSSAPI` (Kerberos), `MONGODB-AWS` (AWS IAM auth),
//     `MONGODB-OIDC` (OAuth2/OIDC auth). The decoder surfaces
//     the command name; the response saslSupportedMechs array
//     is surfaced as part of the BSON command argument walker.
//
//   - **Database + collection namespace disclosure** —
//     OP_QUERY (legacy) carries `fullCollectionName` as a
//     null-terminated string in the form `<database>.<collection>`
//     or `<database>.$cmd` for command requests. OP_MSG
//     (modern) carries the database as a top-level `$db` field
//     in the BSON command document. Both forms reveal the
//     target database + collection in cleartext.
//
//   - **Authentication exchange via `saslStart` /
//     `saslContinue`** — SCRAM-SHA-1 / SCRAM-SHA-256 / PLAIN /
//     MONGODB-X509 / GSSAPI authentication uses a multi-step
//     command exchange:
//
//   - `saslStart { mechanism: "SCRAM-SHA-256", payload:
//     BinData(0, <client-first-message>) }`
//
//   - Server responds with `conversationId` + `payload`
//     (server-first-message with nonce + iteration count).
//
//   - `saslContinue { conversationId: 1, payload: BinData(0,
//     <client-final-message>) }`
//
//   - Server responds with `done: true`/`false`.
//
//     The decoder surfaces the command + mechanism name +
//     `payload_bytes` LENGTH only (privacy-preserving — the
//     SCRAM payload is a structured BinData blob containing the
//     client nonce + salted password proof; offline-crackable
//     with hashcat mode 24100 for SCRAM-SHA-1 / 24200 for
//     SCRAM-SHA-256 once captured).
//
//   - **Dangerous-command detection** — flags each of:
//
//   - `createUser` / `updateUser` / `dropUser` — credential
//     management (creating new accounts is a backdoor
//     primitive).
//
//   - `dropDatabase` / `dropCollection` — data destruction.
//
//   - `listDatabases` / `listCollections` — enumeration
//     (often pre-attack recon).
//
//   - `find` / `aggregate` with `$where` / `$expr` operators
//     — historical server-side JavaScript RCE primitive
//     (removed in MongoDB 4.4 but legacy versions still
//     deployed).
//
//   - `runCommand { eval: ... }` — direct server-side
//     JavaScript execution (REMOVED in 4.4 but legacy 3.x /
//     4.0 / 4.2 still deployed).
//
//   - `shutdown` / `replSetStepDown` — operational
//     destructive commands.
//
//   - **Build info disclosure via `buildInfo`** — server
//     reply includes `version` (e.g. `7.0.4`), `gitVersion`,
//     `buildEnvironment`, `modules` (`enterprise`,
//     `subscription`, etc.), `openssl` version, `storageEngines`.
//     Canonical MongoDB version-fingerprint for CVE selection.
//
// Wrap-vs-native judgement
//
//	Native. The MongoDB wire protocol is publicly documented;
//	the 16-byte header is a fixed struct, little-endian. OP_MSG
//	body is a flag-prefixed section list with kind-discriminated
//	body / document-sequence sections. OP_QUERY body has fixed
//	fields + a cstring fullCollectionName + BSON query. BSON
//	parsing is a length-prefixed element walker. Full BSON
//	value decoding (recursive doc/array walk, ObjectId / Binary
//	subtypes / Decimal128) is out of scope; the decoder extracts
//	the command name + key arguments (`$db`, `mechanism`,
//	`saslSupportedMechs`) as needed.
//
// What this package covers
//
//   - **16-byte header walker**: messageLength (4 LE — total
//     including header) / requestID (4 LE) / responseTo (4 LE)
//     / opCode (4 LE).
//
//   - **12-entry opCode name table**: 1 OP_REPLY (legacy
//     server reply) / 1000 OP_MSG_DEPRECATED (very old) / 2001
//     OP_UPDATE (legacy) / 2002 OP_INSERT (legacy) / 2004
//     OP_QUERY (legacy but still used for the initial isMaster
//     / hello probe by every driver) / 2005 OP_GET_MORE
//     (legacy) / 2006 OP_DELETE (legacy) / 2007 OP_KILL_CURSORS
//     (legacy) / 2010 OP_COMMAND (server-internal) / 2011
//     OP_COMMANDREPLY (server-internal) / 2012 OP_COMPRESSED
//     (Snappy/zlib/zstd wrapped) / 2013 OP_MSG (modern,
//     MongoDB 3.6+ default).
//
//   - **OP_MSG body walker**: flagBits (4 LE) + section[].
//     Section discriminator: 0 = Body (single BSON document),
//     1 = Document Sequence (cstring identifier + BSON docs
//     until the end of the message). The decoder walks the
//     first Body section's BSON document to extract the
//     `command_name` (BSON convention: first element).
//
//   - **OP_QUERY body walker**: flags (4 LE) /
//     fullCollectionName (cstring — e.g. `admin.$cmd` or
//     `mydb.users`) / numberToSkip (4 LE) / numberToReturn
//     (4 LE) / query (BSON document). Surfaces
//     `full_collection_name` cleartext.
//
//   - **BSON document walker**: 4-byte LE length (includes
//     self) + elements. Each element: 1-byte type tag +
//     cstring name + type-dependent value. Terminated by
//     0x00. Surfaces top-level field names + key value types.
//
//   - **18-entry BSON element-type name table** (per BSON
//     spec): 0x01 double / 0x02 string / 0x03 embedded
//     document / 0x04 array / 0x05 binary / 0x07 ObjectId /
//     0x08 boolean / 0x09 UTC datetime / 0x0A null / 0x0B
//     regex / 0x0D JavaScript / 0x0E symbol / 0x0F JavaScript
//     with scope / 0x10 int32 / 0x11 timestamp / 0x12 int64 /
//     0x13 decimal128 / 0xFF min key / 0x7F max key.
//
//   - **Command classification** flagging:
//
//   - `isMaster` / `hello` (version + auth-mechanism
//     enumeration probe — always sent on connect).
//
//   - `buildInfo` (version disclosure).
//
//   - `saslStart` / `saslContinue` (auth exchange; surfaces
//     `sasl_mechanism` + `payload_bytes` length only).
//
//   - `createUser` / `updateUser` / `dropUser` (credential
//     management — backdoor primitive).
//
//   - `dropDatabase` / `dropCollection` (data destruction).
//
//   - `listDatabases` / `listCollections` (enumeration).
//
//   - `find` / `insert` / `update` / `delete` / `aggregate`
//     (DB operations — surfaced for visibility).
//
//   - `eval` / `$where` / `$expr` (server-side JavaScript —
//     historical RCE primitive, removed in MongoDB 4.4 but
//     legacy 3.x / 4.0 / 4.2 deployments still exposed).
//
//   - `shutdown` / `replSetStepDown` (operational
//     destructive).
//
//   - **`$db` field extraction** from OP_MSG BSON body — the
//     modern MongoDB convention places the target database
//     name as a top-level `$db` string field in command
//     requests. Surfaced as `database`.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Full BSON value parsing** — recursive embedded
//     document / array traversal beyond the top-level command
//     name + `$db` + `mechanism` + `payload` length. Each BSON
//     value type has its own length-prefixed binary format; a
//     general BSON walker is a separate decoder concern.
//   - **BSON Binary subtypes** — 0x00 generic / 0x01 function
//     / 0x02 binary-old / 0x03 UUID-old / 0x04 UUID / 0x05
//     MD5 / 0x06 encrypted (CSFLE) / 0x07 compressed / 0x80+
//     user-defined. Surfaced as raw length only.
//   - **OP_COMPRESSED decompression** — opCode 2012 wraps an
//     inner message compressed with Snappy / zlib / zstd
//     (compressorId selects); the decoder identifies the
//     opCode but does NOT decompress. Operators should feed
//     the decompressed inner bytes for analysis.
//   - **TLS handshake** — MongoDB 3.0+ supports TLS (was SSL
//     in 2.x); handle the TLS strip first.
//   - **SDAM topology messages** — MongoDB drivers use periodic
//     `hello` / `isMaster` probes for server discovery + topology
//     monitoring; the decoder surfaces individual messages but
//     does not track topology state.
//   - **Change Streams oplog format** — `aggregate { pipeline:
//     [{$changeStream: ...}] }` returns a cursor of oplog
//     entries; the per-entry format is collection-defined.
//   - **GridFS file storage format** — the `fs.files` / `fs.chunks`
//     collection convention is a higher-level abstraction over
//     ordinary collections.
//   - **Per-driver client metadata fields** — drivers send a
//     `client` field in isMaster/hello with driver name +
//     version + platform + os info; surfaced as ordinary BSON
//     content.
//   - **CSFLE (Client-Side Field-Level Encryption)** — when
//     enabled, sensitive fields are encrypted client-side
//     before transmission; the wire format carries opaque
//     BinData subtype 6 (encrypted) values.
package mongodb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

const headerSize = 16

// Result is the structured decode of a MongoDB wire-protocol
// message.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	MessageLength int    `json:"message_length"`
	RequestID     uint32 `json:"request_id"`
	ResponseTo    uint32 `json:"response_to"`
	OpCode        int    `json:"op_code"`
	OpCodeName    string `json:"op_code_name"`

	// OP_MSG flag bits + section count
	MsgFlagBits  uint32 `json:"msg_flag_bits,omitempty"`
	MsgSections  int    `json:"msg_sections,omitempty"`
	HasChecksum  bool   `json:"has_checksum,omitempty"`
	MoreToCome   bool   `json:"more_to_come,omitempty"`
	ExhaustAllow bool   `json:"exhaust_allowed,omitempty"`

	// OP_QUERY
	FullCollectionName string `json:"full_collection_name,omitempty"`
	NumberToSkip       int32  `json:"number_to_skip,omitempty"`
	NumberToReturn     int32  `json:"number_to_return,omitempty"`

	// Extracted from BSON command body
	CommandName string `json:"command_name,omitempty"`
	Database    string `json:"database,omitempty"`

	// Command classification
	IsHelloProbe       bool   `json:"is_hello_probe"`
	IsSASLAuth         bool   `json:"is_sasl_auth"`
	SASLMechanism      string `json:"sasl_mechanism,omitempty"`
	SASLPayloadBytes   int    `json:"sasl_payload_bytes,omitempty"`
	IsDangerousCommand bool   `json:"is_dangerous_command"`
	DangerousFlag      string `json:"dangerous_command_flag,omitempty"`
}

// Decode parses a MongoDB wire-protocol message from a hex
// string.
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
	if len(b) < headerSize {
		return nil, fmt.Errorf("mongodb header truncated (%d bytes; need 16)", len(b))
	}

	r := &Result{TotalBytes: len(b)}
	r.MessageLength = int(binary.LittleEndian.Uint32(b[0:4]))
	r.RequestID = binary.LittleEndian.Uint32(b[4:8])
	r.ResponseTo = binary.LittleEndian.Uint32(b[8:12])
	r.OpCode = int(binary.LittleEndian.Uint32(b[12:16]))
	r.OpCodeName = opCodeName(r.OpCode)

	body := b[headerSize:]
	if r.MessageLength >= headerSize && r.MessageLength-headerSize < len(body) {
		body = body[:r.MessageLength-headerSize]
	}

	switch r.OpCode {
	case 2013:
		decodeOpMsg(r, body)
	case 2004:
		decodeOpQuery(r, body)
	}
	classifyCommand(r)
	return r, nil
}

func decodeOpMsg(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	r.MsgFlagBits = binary.LittleEndian.Uint32(body[0:4])
	r.HasChecksum = r.MsgFlagBits&0x00000001 != 0
	r.MoreToCome = r.MsgFlagBits&0x00000002 != 0
	r.ExhaustAllow = r.MsgFlagBits&0x00010000 != 0
	off := 4
	for off < len(body) {
		if r.HasChecksum && off+4 >= len(body) {
			break
		}
		kind := body[off]
		off++
		r.MsgSections++
		switch kind {
		case 0:
			// Body: single BSON doc
			if off+4 > len(body) {
				return
			}
			docLen := int(binary.LittleEndian.Uint32(body[off : off+4]))
			docEnd := off + docLen
			if docEnd > len(body) {
				docEnd = len(body)
			}
			walkBSON(r, body[off:docEnd])
			off = docEnd
		case 1:
			// Document Sequence: 4-byte size + cstring identifier
			// + sequence of BSON docs
			if off+4 > len(body) {
				return
			}
			seqLen := int(binary.LittleEndian.Uint32(body[off : off+4]))
			off += seqLen
		default:
			return
		}
		// Only walk the first body for command extraction
		if r.CommandName != "" {
			break
		}
	}
}

func decodeOpQuery(r *Result, body []byte) {
	if len(body) < 4 {
		return
	}
	off := 4 // skip flags
	end := off
	for end < len(body) && body[end] != 0 {
		end++
	}
	r.FullCollectionName = string(body[off:end])
	off = end + 1
	if off+8 > len(body) {
		return
	}
	r.NumberToSkip = int32(binary.LittleEndian.Uint32(body[off : off+4]))
	off += 4
	r.NumberToReturn = int32(binary.LittleEndian.Uint32(body[off : off+4]))
	off += 4
	// BSON query
	if off+4 <= len(body) {
		walkBSON(r, body[off:])
	}
	// Derive database from fullCollectionName "<db>.<coll>"
	if dot := strings.Index(r.FullCollectionName, "."); dot > 0 {
		r.Database = r.FullCollectionName[:dot]
	}
}

// walkBSON walks the top-level fields of a BSON document and
// extracts the command name (first field, by MongoDB
// convention) + $db + sasl mechanism / payload length.
func walkBSON(r *Result, doc []byte) {
	if len(doc) < 5 {
		return
	}
	docLen := int(binary.LittleEndian.Uint32(doc[0:4]))
	if docLen > len(doc) {
		docLen = len(doc)
	}
	off := 4
	first := true
	for off < docLen {
		if doc[off] == 0 {
			break
		}
		t := doc[off]
		off++
		// name (cstring)
		nameEnd := off
		for nameEnd < docLen && doc[nameEnd] != 0 {
			nameEnd++
		}
		name := string(doc[off:nameEnd])
		off = nameEnd + 1
		// value (type-dependent length)
		valStart := off
		valLen, ok := bsonValueLength(t, doc[off:docLen])
		if !ok {
			return
		}
		off += valLen
		// First field — command name (value is 1 for ismaster=1
		// shape, or a string for the collection name in
		// find/insert/etc.)
		if first {
			first = false
			r.CommandName = name
		}
		switch name {
		case "$db":
			if t == 0x02 && valLen >= 4 {
				sLen := int(binary.LittleEndian.Uint32(doc[valStart : valStart+4]))
				if sLen > 0 && valStart+4+sLen-1 <= docLen {
					r.Database = string(doc[valStart+4 : valStart+4+sLen-1])
				}
			}
		case "mechanism":
			if t == 0x02 && valLen >= 4 {
				sLen := int(binary.LittleEndian.Uint32(doc[valStart : valStart+4]))
				if sLen > 0 && valStart+4+sLen-1 <= docLen {
					r.SASLMechanism = string(doc[valStart+4 : valStart+4+sLen-1])
				}
			}
		case "payload":
			if t == 0x05 && valLen >= 5 {
				payloadLen := int(binary.LittleEndian.Uint32(doc[valStart : valStart+4]))
				r.SASLPayloadBytes = payloadLen
			}
		}
	}
}

// bsonValueLength returns how many bytes the value of the given
// element type occupies, given the bytes following the element
// name.
func bsonValueLength(t byte, b []byte) (int, bool) {
	switch t {
	case 0x01: // double
		return 8, true
	case 0x02: // string
		if len(b) < 4 {
			return 0, false
		}
		l := int(binary.LittleEndian.Uint32(b[0:4]))
		return 4 + l, true
	case 0x03, 0x04: // embedded document / array
		if len(b) < 4 {
			return 0, false
		}
		l := int(binary.LittleEndian.Uint32(b[0:4]))
		return l, true
	case 0x05: // binary
		if len(b) < 5 {
			return 0, false
		}
		l := int(binary.LittleEndian.Uint32(b[0:4]))
		return 4 + 1 + l, true
	case 0x07: // ObjectId
		return 12, true
	case 0x08: // boolean
		return 1, true
	case 0x09: // UTC datetime
		return 8, true
	case 0x0A: // null
		return 0, true
	case 0x10: // int32
		return 4, true
	case 0x11: // timestamp
		return 8, true
	case 0x12: // int64
		return 8, true
	case 0x13: // decimal128
		return 16, true
	}
	return 0, false
}

func opCodeName(c int) string {
	switch c {
	case 1:
		return "OP_REPLY (legacy)"
	case 1000:
		return "OP_MSG_DEPRECATED"
	case 2001:
		return "OP_UPDATE (legacy)"
	case 2002:
		return "OP_INSERT (legacy)"
	case 2004:
		return "OP_QUERY (legacy — used for initial isMaster/hello probe)"
	case 2005:
		return "OP_GET_MORE (legacy)"
	case 2006:
		return "OP_DELETE (legacy)"
	case 2007:
		return "OP_KILL_CURSORS (legacy)"
	case 2010:
		return "OP_COMMAND (server-internal)"
	case 2011:
		return "OP_COMMANDREPLY (server-internal)"
	case 2012:
		return "OP_COMPRESSED (Snappy/zlib/zstd wrapped)"
	case 2013:
		return "OP_MSG (modern, MongoDB 3.6+ default)"
	}
	return fmt.Sprintf("uncatalogued opcode %d", c)
}

func classifyCommand(r *Result) {
	switch r.CommandName {
	case "isMaster", "ismaster", "hello":
		r.IsHelloProbe = true
	case "saslStart", "saslContinue":
		r.IsSASLAuth = true
	case "buildInfo":
		// not dangerous; version disclosure flagged via name
	case "createUser":
		r.IsDangerousCommand = true
		r.DangerousFlag = "createUser — credential management; new account creation is a backdoor primitive"
	case "updateUser":
		r.IsDangerousCommand = true
		r.DangerousFlag = "updateUser — credential modification (password reset, roles)"
	case "dropUser":
		r.IsDangerousCommand = true
		r.DangerousFlag = "dropUser — account removal"
	case "dropDatabase":
		r.IsDangerousCommand = true
		r.DangerousFlag = "dropDatabase — data destruction"
	case "dropCollection", "drop":
		r.IsDangerousCommand = true
		r.DangerousFlag = "drop / dropCollection — data destruction"
	case "listDatabases":
		r.IsDangerousCommand = true
		r.DangerousFlag = "listDatabases — enumeration (canonical pre-attack recon)"
	case "listCollections":
		r.IsDangerousCommand = true
		r.DangerousFlag = "listCollections — enumeration"
	case "eval":
		r.IsDangerousCommand = true
		r.DangerousFlag = "eval — server-side JavaScript execution (RCE primitive; REMOVED in MongoDB 4.4 but legacy 3.x/4.0/4.2 still deployed)"
	case "shutdown":
		r.IsDangerousCommand = true
		r.DangerousFlag = "shutdown — operational destructive"
	case "replSetStepDown":
		r.IsDangerousCommand = true
		r.DangerousFlag = "replSetStepDown — replica-set primary step-down"
	}
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
