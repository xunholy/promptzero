// mongodb.go — host-side MongoDB wire-protocol decoder Spec.
// Wraps the internal/mongodb walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mongodb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mongodbDecodeSpec)
}

var mongodbDecodeSpec = Spec{
	Name: "mongodb_decode",
	Description: "Decode a MongoDB wire-protocol message per the MongoDB " +
		"documentation. TCP/27017 default (mongod); TCP/27018 (mongos " +
		"sharded router); TCP/27019 (config servers). Compatible with " +
		"FerretDB (Postgres-backed MongoDB-compatible proxy) and AWS " +
		"DocumentDB (MongoDB-compatible). High-value NoSQL pentest " +
		"target with exposure profile similar to Redis — historical " +
		"deployments (Mongo 2.x / 3.x) defaulted to \"no auth, bind to " +
		"0.0.0.0\"; Shodan still finds tens of thousands of " +
		"unauthenticated MongoDB instances on TCP/27017. Modern MongoDB " +
		"(4.x+) defaults to localhost-only binding + SCRAM-SHA-256 " +
		"auth. The wire format leaks: **MongoDB version + auth-" +
		"mechanism enumeration via isMaster/hello** (every driver sends " +
		"this on connect; server reply includes maxWireVersion + " +
		"topologyVersion + setName + primary/hosts + me + " +
		"saslSupportedMechs array: SCRAM-SHA-1 legacy weak / SCRAM-" +
		"SHA-256 modern default / PLAIN cleartext / MONGODB-X509 / " +
		"GSSAPI Kerberos / MONGODB-AWS IAM / MONGODB-OIDC); **database " +
		"+ collection namespace cleartext** (OP_QUERY fullCollectionName " +
		"\"<db>.<coll>\" or \"<db>.$cmd\"; OP_MSG $db top-level field); " +
		"**authentication exchange via saslStart/saslContinue** (multi-" +
		"step SCRAM-SHA-256 — surfaces mechanism + payload_bytes LENGTH " +
		"only, privacy-preserving; offline-crackable with hashcat mode " +
		"24100 SCRAM-SHA-1 / 24200 SCRAM-SHA-256 once captured); " +
		"**dangerous-command detection** (createUser/updateUser/dropUser " +
		"= credential management backdoor primitive; dropDatabase/" +
		"dropCollection = data destruction; listDatabases/" +
		"listCollections = enumeration; eval / $where / $expr = server-" +
		"side JavaScript RCE primitive REMOVED in 4.4 but legacy 3.x/" +
		"4.0/4.2 still deployed; shutdown/replSetStepDown = operational " +
		"destructive); **build info disclosure via buildInfo** (version " +
		"+ gitVersion + buildEnvironment + modules + openssl + " +
		"storageEngines — canonical CVE-selection fingerprint). " +
		"Decodes:\n\n" +
		"- **16-byte header walker**: messageLength (4 LE — total incl " +
		"header) / requestID / responseTo / opCode.\n" +
		"- **12-entry opCode name table**: 1 OP_REPLY (legacy server " +
		"reply) / 1000 OP_MSG_DEPRECATED / 2001 OP_UPDATE / 2002 " +
		"OP_INSERT / 2004 OP_QUERY (legacy but still used for initial " +
		"isMaster/hello probe by every driver) / 2005 OP_GET_MORE / " +
		"2006 OP_DELETE / 2007 OP_KILL_CURSORS / 2010 OP_COMMAND " +
		"(server-internal) / 2011 OP_COMMANDREPLY / 2012 OP_COMPRESSED " +
		"(Snappy/zlib/zstd wrapped) / 2013 OP_MSG (modern MongoDB 3.6+ " +
		"default).\n" +
		"- **OP_MSG body walker**: flagBits + section[]. Section kinds: " +
		"0 = Body (single BSON doc) / 1 = Document Sequence (cstring " +
		"identifier + BSON docs). Surfaces `msg_flag_bits` + " +
		"`msg_sections` + `has_checksum` + `more_to_come` + " +
		"`exhaust_allowed` flag classifications.\n" +
		"- **OP_QUERY body walker**: flags + fullCollectionName + " +
		"numberToSkip + numberToReturn + BSON query. Surfaces " +
		"`full_collection_name` cleartext.\n" +
		"- **BSON document walker**: 4-byte LE length + elements (1-byte " +
		"type + cstring name + type-dependent value) terminated by 0x00. " +
		"Walks top-level fields to extract `command_name` (BSON " +
		"convention: first field) + `$db` (target database) + " +
		"`mechanism` (SASL) + `payload` (SASL payload length only — " +
		"privacy-preserving).\n" +
		"- **18-entry BSON element-type name table**: 0x01 double / " +
		"0x02 string / 0x03 embedded doc / 0x04 array / 0x05 binary / " +
		"0x07 ObjectId / 0x08 boolean / 0x09 UTC datetime / 0x0A null / " +
		"0x0B regex / 0x0D JavaScript / 0x0E symbol / 0x0F JavaScript " +
		"with scope / 0x10 int32 / 0x11 timestamp / 0x12 int64 / 0x13 " +
		"decimal128 / 0xFF min key / 0x7F max key.\n" +
		"- **Command classification**: `is_hello_probe` boolean for " +
		"isMaster/ismaster/hello + `is_sasl_auth` boolean for saslStart/" +
		"saslContinue + `is_dangerous_command` + `dangerous_command_flag` " +
		"for createUser/updateUser/dropUser/dropDatabase/" +
		"dropCollection/listDatabases/listCollections/eval/shutdown/" +
		"replSetStepDown.\n\n" +
		"Pure offline parser — operators paste MongoDB bytes (the TCP-" +
		"segment payload as hex; default TCP/27017 + 27018 mongos + " +
		"27019 config) from a `tcpdump -X port 27017` line or a " +
		"Wireshark Mongo dissector view and get the documented per-" +
		"message breakdown.\n\n" +
		"Out of scope (deferred): full BSON value parsing (recursive " +
		"embedded document/array traversal beyond top-level command " +
		"name + $db + mechanism + payload length; general BSON walker " +
		"is a separate decoder concern); BSON Binary subtypes (0x00 " +
		"generic / 0x01 function / 0x02 binary-old / 0x03 UUID-old / " +
		"0x04 UUID / 0x05 MD5 / 0x06 encrypted CSFLE / 0x07 compressed " +
		"/ 0x80+ user-defined — surfaced as length only); OP_COMPRESSED " +
		"decompression (opCode 2012 wraps inner message with Snappy / " +
		"zlib / zstd; decoder identifies opCode but does NOT decompress " +
		"— feed decompressed inner bytes); TLS handshake (MongoDB 3.0+ " +
		"supports TLS — handle TLS strip first); SDAM topology " +
		"monitoring (drivers send periodic hello probes for server " +
		"discovery); Change Streams oplog format; GridFS file storage " +
		"format (fs.files / fs.chunks convention); per-driver client " +
		"metadata fields (driver name + version + platform + os); " +
		"CSFLE (Client-Side Field-Level Encryption) opaque BinData " +
		"subtype 6 values.\n\n" +
		"Source: docs/catalog/gap-analysis.md (database-protocol " +
		"foundational decoder — canonical MongoDB pentest dissector for " +
		"isMaster/hello probing + saslStart auth-mechanism capture + " +
		"BSON command-name extraction + dangerous-command flagging + " +
		"version fingerprint; pairs with redis_decode + tds_decode + " +
		"postgres_decode + mysql_decode for the cross-database pentest " +
		"surface — every common DB protocol now has a native dissector; " +
		"common in DEF CON + Black Hat + HITB + OffSec engagements + " +
		"every nmap mongodb-* NSE / metasploit mongodb_login / nosqlmap " +
		"/ mongo-shell-driven MongoDB attack workflow). Wrap-vs-native: " +
		"native — MongoDB wire protocol is publicly documented; 16-byte " +
		"header fixed struct LE; OP_MSG body is flag-prefixed section " +
		"list with kind-discriminated sections; BSON parsing is a " +
		"length-prefixed element walker; full BSON value decode + " +
		"recursive doc/array traversal + ObjectId/Decimal128/Binary " +
		"subtype handling out of scope; no crypto at the parse layer; " +
		"SASL payload contents NEVER decoded (payload_bytes length only " +
		"— privacy-preserving while flagging the auth exposure).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"MongoDB wire-protocol message bytes as hex (the TCP-segment payload; default TCP/27017 + 27018 mongos + 27019 config). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mongodbDecodeHandler,
}

func mongodbDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("mongodb_decode: 'hex' is required")
	}
	res, err := mongodb.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("mongodb_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
