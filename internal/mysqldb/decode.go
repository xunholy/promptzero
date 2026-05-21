// Package mysqldb decodes MySQL / MariaDB client/server protocol
// messages per the MySQL documentation (Chapter 4: "Client/Server
// Protocol"). Runs on TCP/3306 default; also seen via Unix
// sockets, and MySQL Group Replication on TCP/33061. Compatible
// with MariaDB which uses the same wire format with minor
// extensions.
//
// Operationally, MySQL is the **largest open-source database
// pentest target** — deployed everywhere from cloud-managed
// MySQL (RDS / Aurora / Cloud SQL / Azure Database / PlanetScale)
// to bare-metal installations to containerized side-cars to
// every shared-hosting cPanel deployment. Together with
// `tds_decode` (v0.334) + `postgres_decode` (v0.335) this
// completes the **database-protocol pentest trio** (MSSQL +
// PostgreSQL + MySQL/MariaDB).
//
// The wire format leaks:
//
//   - **Server fingerprint via Handshake v10** — the first
//     packet after TCP connect is a server-initiated Handshake
//     v10 containing the **server_version** string (null-
//     terminated) — typically `8.0.35-0ubuntu0.22.04.1`,
//     `5.7.42`, `10.11.5-MariaDB`, `Percona Server 8.0.34-26`.
//     This is the canonical MySQL version-fingerprint for CVE
//     selection.
//
//   - **Authentication plugin negotiation via Handshake v10
//     auth_plugin_name** — when the CLIENT_PLUGIN_AUTH bit is
//     set, the server's preferred auth plugin is null-
//     terminated at the end of the Handshake. The plugin name
//     reveals the auth-security posture:
//
//   - `mysql_native_password` — **SHA1-based, offline-
//     crackable** (hashcat mode 11200 / 300). Legacy MySQL
//     default; still common in MySQL 5.7 and MariaDB.
//
//   - `caching_sha2_password` — **modern MySQL 8 default**;
//     SHA-256-based, cache-on-first-success. Harder to crack
//     offline but the wire exchange exposes whether the
//     fast-auth (cached) path was hit.
//
//   - `sha256_password` — RSA-encrypted password exchange;
//     requires SSL or RSA public-key transfer.
//
//   - `mysql_clear_password` — **password sent IN CLEARTEXT**
//     over the wire (used with PAM auth or LDAP-backed auth);
//     **MITM-capturable!**
//
//   - `auth_socket` — Unix-socket-only peer-credentials auth;
//     no password on the wire (typical for `root@localhost`
//     in modern MySQL/MariaDB defaults).
//
//   - `windows_native_password` — Windows SSPI / NTLM
//     integration.
//
//   - `dialog` — interactive multi-step plugin (Percona
//     PAM, MariaDB Cracklib); typically wraps a clear or
//     hashed exchange.
//
//   - **TLS support via CLIENT_SSL capability bit** — the
//     server advertises `CLIENT_SSL` (0x00000800) in the
//     Handshake capability flags when SSL is supported. A
//     client that proceeds with HandshakeResponse41 **without
//     a TLS upgrade in between** sends the username + auth
//     data in cleartext on TCP/3306 — the canonical MySQL
//     credential-disclosure scenario.
//
//   - **Cleartext username via HandshakeResponse41** — the
//     second packet (sequence ID 1, client → server) is the
//     HandshakeResponse41 containing the **username** as a
//     null-terminated UTF-8 string. Surfaced as cleartext
//     `user_name`.
//
//   - **Cleartext database via CLIENT_CONNECT_WITH_DB** —
//     when the CLIENT_CONNECT_WITH_DB capability bit is set,
//     HandshakeResponse41 carries the target database name
//     as a null-terminated UTF-8 string after the auth-data
//     section. Surfaced as cleartext `database`.
//
//   - **Brute-force feedback via ERR packet 1045** — failed
//     authentication returns an ERR packet (`0xFF` header)
//     with error code 1045 (`ER_ACCESS_DENIED_ERROR` — "Access
//     denied for user 'user'@'host'"). Password-spray tools
//     (`mysql -u admin -p`, hydra mysql, nmap mysql-brute NSE,
//     metasploit mysql_login) consume this directly. Error
//     code 1049 (`ER_BAD_DB_ERROR` — "Unknown database 'db'")
//     is the canonical database-enumeration feedback.
//
//   - **Connection ID disclosure** — every Handshake carries
//     a 4-byte LE connection_id; this is stable per-connection
//     and enumerable (sequential allocation) for traffic
//     analysis.
//
// Wrap-vs-native judgement
//
//	Native. The MySQL client/server protocol is publicly
//	documented (MySQL Reference Manual Chapter 4). The
//	packet format is a simple 3+1-byte length+sequence
//	header + payload. Handshake v10 + HandshakeResponse41 +
//	ERR are deterministic struct walks (with capability-bit-
//	gated optional fields). COM_QUERY / COM_INIT_DB / 32+
//	other command-specific bodies, result-set parsing,
//	prepared-statement binary-protocol parameter marshalling,
//	compressed packet format, SSL handshake, and the full
//	caching_sha2_password RSA exchange are out of scope.
//
// What this package covers
//
//   - **4-byte packet header**: 3-byte LE length + 1-byte
//     sequence ID. Sequence resets to 0 at the start of each
//     command and increments by 1 for each subsequent packet
//     in the response chain.
//
//   - **Handshake v10 body walker** (server → client, first
//     packet, sequence 0): protocol_version (0x0A) + null-
//     terminated server_version + 4-byte LE connection_id +
//     8-byte auth-plugin-data-part-1 + 0x00 filler + 2-byte
//     LE capability flags lower + 1-byte character set + 2-
//     byte LE status flags + 2-byte LE capability flags upper
//
//   - 1-byte auth-plugin-data length + 10 bytes reserved +
//     auth-plugin-data-part-2 + null-terminated auth_plugin_name
//     (if CLIENT_PLUGIN_AUTH bit set).
//
//   - **HandshakeResponse41 body walker** (client → server,
//     second packet, sequence 1): 4-byte LE capability flags
//
//   - 4-byte LE max_packet_size + 1-byte character set + 23
//     bytes filler + null-terminated username + length-prefixed
//     or null-terminated auth-data + (if CLIENT_CONNECT_WITH_DB)
//     null-terminated database + (if CLIENT_PLUGIN_AUTH) null-
//     terminated client_plugin_name. Surfaces `user_name`,
//     `database`, `client_plugin_name`, and `auth_data_bytes`
//     LENGTH only (privacy-preserving — never the auth-data
//     itself).
//
//   - **ERR packet walker** (server → client, response to a
//     failed command): 0xFF header + 2-byte LE error code +
//     (if CLIENT_PROTOCOL_41) 0x23 marker + 5-byte SQL state
//
//   - error message (runs to end of packet, no null
//     terminator). Surfaces `error_code` + `error_code_name`
//
//   - `sql_state` + `error_message`.
//
//   - **OK packet detection** — 0x00 header + length-encoded
//     affected_rows + length-encoded last_insert_id + 2-byte
//     LE status flags + 2-byte LE warnings + (CLIENT_SESSION_
//     TRACK gated) info string. Surfaced as `is_ok_packet`
//     boolean.
//
//   - **EOF packet detection** — 0xFE header + 2-byte LE
//     warnings + 2-byte LE status flags (when CLIENT_DEPRECATE
//     _EOF is NOT set; MySQL 8 deprecates EOF in favor of
//     OK markers). Surfaced as `is_eof_packet` boolean.
//
//   - **25-entry capability flags name table**: CLIENT_LONG
//     _PASSWORD (0x00001) / CLIENT_FOUND_ROWS / CLIENT_LONG
//     _FLAG / CLIENT_CONNECT_WITH_DB (0x00008) / CLIENT_NO
//     _SCHEMA / CLIENT_COMPRESS (0x00020) / CLIENT_ODBC /
//     CLIENT_LOCAL_FILES (0x00080) / CLIENT_IGNORE_SPACE /
//     CLIENT_PROTOCOL_41 (0x00200) / CLIENT_INTERACTIVE /
//     CLIENT_SSL (0x00800 — TLS support!) / CLIENT_IGNORE_
//     SIGPIPE / CLIENT_TRANSACTIONS / CLIENT_RESERVED /
//     CLIENT_SECURE_CONNECTION (0x08000) / CLIENT_MULTI_
//     STATEMENTS / CLIENT_MULTI_RESULTS / CLIENT_PS_MULTI_
//     RESULTS / CLIENT_PLUGIN_AUTH (0x80000) / CLIENT_CONNECT
//     _ATTRS / CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA /
//     CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS / CLIENT_SESSION
//     _TRACK / CLIENT_DEPRECATE_EOF / CLIENT_SSL_VERIFY_SERVER
//     _CERT (0x40000000).
//
//   - **5-entry status flags name table**: SERVER_STATUS
//     _IN_TRANS (0x0001) / SERVER_STATUS_AUTOCOMMIT (0x0002)
//     / SERVER_MORE_RESULTS_EXISTS (0x0008) / SERVER_QUERY
//     _NO_GOOD_INDEX_USED (0x0010) / SERVER_QUERY_NO_INDEX
//     _USED (0x0020).
//
//   - **7-entry auth plugin name table** flagging each
//     plugin with its security characterization: mysql_native
//     _password (SHA1-weak — offline-crackable hashcat mode
//     11200/300) / caching_sha2_password (modern MySQL 8
//     default — SHA-256 cache-on-first-success) / sha256_
//     password (RSA — requires SSL or pubkey transfer) /
//     mysql_clear_password (cleartext — MITM-capturable!) /
//     auth_socket (Unix peer-credentials — no password on
//     wire) / windows_native_password (NTLM/SSPI) / dialog
//     (interactive multi-step plugin — Percona PAM,
//     MariaDB Cracklib).
//
//   - **11-entry error code name table**: 1044 ER_DBACCESS
//     _DENIED_ERROR / 1045 ER_ACCESS_DENIED_ERROR (canonical
//     brute-force feedback!) / 1049 ER_BAD_DB_ERROR
//     (canonical database enumeration) / 1129 ER_HOST_IS
//     _BLOCKED (too many failures — server-side block) /
//     1130 ER_HOST_NOT_PRIVILEGED (host not allowed) / 1158
//     ER_NET_PACKET_TOO_LARGE / 1251 ER_NOT_SUPPORTED_AUTH
//     _MODE (auth plugin mismatch) / 2059 ER_NO_AUTH_PLUGIN
//     _FOUND / 2061 ER_AUTH_PLUGIN_REQUIRES_SECURE_CONNECTION
//     / 2068 ER_NOT_IMPLEMENTED_FOR_CACHED_PASSWORD / 3950
//     ER_NOT_VALID_PASSWORD.
//
// What this package does NOT cover (deliberately out of scope)
//
//   - **Command-specific bodies** — COM_QUERY (0x03 — the
//     SQL query text), COM_INIT_DB (0x02), COM_STMT_PREPARE
//     (0x16) + COM_STMT_EXECUTE (0x17), COM_STMT_CLOSE,
//     COM_REGISTER_SLAVE (0x15 — replication), COM_BINLOG
//     _DUMP, COM_CHANGE_USER, and 25+ other command bodies
//     are not decoded individually; the decoder surfaces
//     the packet header + the command byte if present.
//   - **Result-set parsing** — TextResultSet (ColumnCount +
//     N×ColumnDefinition41 + EOF/OK_Packet + N×ResultsetRow
//   - EOF/OK_Packet) and BinaryResultSet (prepared-
//     statement variant); each requires multi-packet state
//     tracking. Out of scope.
//   - **Binary-protocol prepared-statement parameter
//     marshalling** — COM_STMT_EXECUTE carries N parameters
//     with null-bitmap + per-parameter type + per-parameter
//     value; each value typed via prior COM_STMT_PREPARE's
//     type list. Out of scope.
//   - **Compressed packet format** (CLIENT_COMPRESS) — when
//     compression is negotiated, each on-the-wire packet is
//     prefixed with a 7-byte compressed-packet header
//     (compressed length + sequence + uncompressed length)
//     and the payload is zlib-compressed. Out of scope; feed
//     decompressed bytes.
//   - **SSL handshake** — after CLIENT_SSL is set in the
//     HandshakeResponse41 capability flags AND a SSLRequest
//     packet (HandshakeResponse41 truncated at the 23-byte
//     filler) is sent, the connection upgrades to TLS;
//     subsequent MySQL packets ride inside the TLS record
//     layer. Handle TLS strip first.
//   - **caching_sha2_password full-auth exchange** — when
//     the fast-auth (cache) path misses, the server requests
//     full authentication via a 0x04 marker; the client
//     either uses TLS to send the cleartext password OR
//     requests the server's RSA public key (0x02 marker) and
//     sends the password XOR-with-scramble RSA-encrypted.
//     Out of scope.
//   - **LOAD DATA LOCAL INFILE** — the server can respond to
//     a COM_QUERY with a 0xFB header indicating "send file
//     content" — a known abuse vector (MySQL client → server
//     file exfiltration). Detected via the 0xFB header but
//     not decoded.
//   - **MariaDB-specific extensions** — MariaDB capability
//     flags (MARIADB_CLIENT_PROGRESS, MARIADB_CLIENT_COM
//     _MULTI, MARIADB_CLIENT_STMT_BULK_OPERATIONS) and
//     authentication plugins (ed25519, mysql_clear_password
//     variants) follow the same packet shape but use
//     additional capability bits. Generic mysql_decode
//     handles the common subset.
//   - **XA / GTID / replication-specific semantics** —
//     replication events, binlog packets, and XA transaction
//     prepare/commit/rollback packets are not decoded.
package mysqldb

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// Result is the structured decode of a MySQL packet.
type Result struct {
	TotalBytes int `json:"total_bytes"`

	PayloadLength int `json:"payload_length"`
	SequenceID    int `json:"sequence_id"`

	// Classification
	IsHandshake     bool `json:"is_handshake"`
	IsHandshakeResp bool `json:"is_handshake_response"`
	IsERR           bool `json:"is_err_packet"`
	IsOK            bool `json:"is_ok_packet"`
	IsEOF           bool `json:"is_eof_packet"`

	// Handshake v10
	ProtocolVersion  int      `json:"protocol_version,omitempty"`
	ServerVersion    string   `json:"server_version,omitempty"`
	ConnectionID     uint32   `json:"connection_id,omitempty"`
	CapabilityFlags  uint32   `json:"capability_flags,omitempty"`
	CapabilityNames  []string `json:"capability_names,omitempty"`
	StatusFlags      uint16   `json:"status_flags,omitempty"`
	StatusFlagsNames []string `json:"status_flags_names,omitempty"`
	CharacterSet     int      `json:"character_set,omitempty"`
	AuthPluginName   string   `json:"auth_plugin_name,omitempty"`
	AuthPluginDesc   string   `json:"auth_plugin_description,omitempty"`
	SSLSupported     bool     `json:"ssl_supported"`

	// HandshakeResponse41
	UserName         string `json:"user_name,omitempty"`
	Database         string `json:"database,omitempty"`
	ClientPluginName string `json:"client_plugin_name,omitempty"`
	AuthDataBytes    int    `json:"auth_data_bytes,omitempty"`
	MaxPacketSize    uint32 `json:"max_packet_size,omitempty"`

	// ERR packet
	ErrorCode     int    `json:"error_code,omitempty"`
	ErrorCodeName string `json:"error_code_name,omitempty"`
	SQLState      string `json:"sql_state,omitempty"`
	ErrorMessage  string `json:"error_message,omitempty"`
}

// Decode parses a MySQL packet from a hex string.
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
	if len(b) < 5 {
		return nil, fmt.Errorf("mysql packet truncated (%d bytes; need 5)", len(b))
	}

	r := &Result{TotalBytes: len(b)}

	r.PayloadLength = int(uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16)
	r.SequenceID = int(b[3])
	payload := b[4:]
	if r.PayloadLength < len(payload) {
		payload = payload[:r.PayloadLength]
	}
	if len(payload) == 0 {
		return r, nil
	}

	// Classify by first payload byte + sequence ID.
	switch {
	case payload[0] == 0x0A && r.SequenceID == 0:
		r.IsHandshake = true
		decodeHandshake(r, payload)
	case payload[0] == 0xFF:
		r.IsERR = true
		decodeERR(r, payload)
	case payload[0] == 0x00 && len(payload) >= 7:
		// Could be OK packet (heuristic — also could be COM_SLEEP=0)
		r.IsOK = true
	case payload[0] == 0xFE && len(payload) < 9:
		// EOF packet (short — long form is an OK with header 0xFE
		// when CLIENT_DEPRECATE_EOF is set)
		r.IsEOF = true
	default:
		// Heuristic: sequence ID 1 with sufficient length is a
		// HandshakeResponse41
		if r.SequenceID == 1 && len(payload) >= 36 {
			r.IsHandshakeResp = true
			decodeHandshakeResponse(r, payload)
		}
	}
	return r, nil
}

func decodeHandshake(r *Result, p []byte) {
	r.ProtocolVersion = int(p[0])
	off := 1
	// server_version: null-terminated
	end := off
	for end < len(p) && p[end] != 0 {
		end++
	}
	r.ServerVersion = string(p[off:end])
	off = end + 1
	if off+4 > len(p) {
		return
	}
	r.ConnectionID = binary.LittleEndian.Uint32(p[off : off+4])
	off += 4
	// 8 bytes auth-plugin-data-part-1
	off += 8
	if off >= len(p) {
		return
	}
	// 1 byte filler 0x00
	off++
	if off+2 > len(p) {
		return
	}
	capLower := binary.LittleEndian.Uint16(p[off : off+2])
	off += 2
	if off >= len(p) {
		return
	}
	r.CharacterSet = int(p[off])
	off++
	if off+2 > len(p) {
		return
	}
	r.StatusFlags = binary.LittleEndian.Uint16(p[off : off+2])
	r.StatusFlagsNames = statusFlagsNames(r.StatusFlags)
	off += 2
	if off+2 > len(p) {
		r.CapabilityFlags = uint32(capLower)
		r.CapabilityNames = capabilityNames(r.CapabilityFlags)
		r.SSLSupported = r.CapabilityFlags&0x0800 != 0
		return
	}
	capUpper := binary.LittleEndian.Uint16(p[off : off+2])
	off += 2
	r.CapabilityFlags = uint32(capLower) | (uint32(capUpper) << 16)
	r.CapabilityNames = capabilityNames(r.CapabilityFlags)
	r.SSLSupported = r.CapabilityFlags&0x0800 != 0
	// 1 byte auth-plugin-data length
	if off >= len(p) {
		return
	}
	authLen := int(p[off])
	off++
	// 10 bytes reserved
	off += 10
	// auth-plugin-data-part-2: max(13, authLen-8) bytes
	skip := 13
	if authLen-8 > skip {
		skip = authLen - 8
	}
	off += skip
	// auth_plugin_name: null-terminated (if CLIENT_PLUGIN_AUTH)
	if r.CapabilityFlags&0x80000 != 0 && off < len(p) {
		end = off
		for end < len(p) && p[end] != 0 {
			end++
		}
		r.AuthPluginName = string(p[off:end])
		r.AuthPluginDesc = authPluginDescription(r.AuthPluginName)
	}
}

func decodeHandshakeResponse(r *Result, p []byte) {
	if len(p) < 32 {
		return
	}
	r.CapabilityFlags = binary.LittleEndian.Uint32(p[0:4])
	r.CapabilityNames = capabilityNames(r.CapabilityFlags)
	r.SSLSupported = r.CapabilityFlags&0x0800 != 0
	r.MaxPacketSize = binary.LittleEndian.Uint32(p[4:8])
	r.CharacterSet = int(p[8])
	off := 32 // skip 23-byte filler
	// username: null-terminated
	end := off
	for end < len(p) && p[end] != 0 {
		end++
	}
	r.UserName = string(p[off:end])
	off = end + 1
	if off >= len(p) {
		return
	}
	// auth-data: length-prefixed or null-terminated
	var authLen int
	if r.CapabilityFlags&0x00200000 != 0 {
		// CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA — length-encoded int
		authLen = int(p[off])
		off++
	} else if r.CapabilityFlags&0x00008000 != 0 {
		// CLIENT_SECURE_CONNECTION — 1-byte length
		authLen = int(p[off])
		off++
	} else {
		// null-terminated
		end = off
		for end < len(p) && p[end] != 0 {
			end++
		}
		authLen = end - off
	}
	r.AuthDataBytes = authLen
	off += authLen
	// database: null-terminated (if CLIENT_CONNECT_WITH_DB)
	if r.CapabilityFlags&0x00000008 != 0 && off < len(p) {
		end = off
		for end < len(p) && p[end] != 0 {
			end++
		}
		r.Database = string(p[off:end])
		off = end + 1
	}
	// client_plugin_name: null-terminated (if CLIENT_PLUGIN_AUTH)
	if r.CapabilityFlags&0x00080000 != 0 && off < len(p) {
		end = off
		for end < len(p) && p[end] != 0 {
			end++
		}
		r.ClientPluginName = string(p[off:end])
	}
}

func decodeERR(r *Result, p []byte) {
	if len(p) < 3 {
		return
	}
	r.ErrorCode = int(binary.LittleEndian.Uint16(p[1:3]))
	r.ErrorCodeName = errorCodeName(r.ErrorCode)
	off := 3
	// CLIENT_PROTOCOL_41 marker: 0x23 + 5-byte SQL state
	if off < len(p) && p[off] == '#' {
		off++
		if off+5 <= len(p) {
			r.SQLState = string(p[off : off+5])
			off += 5
		}
	}
	r.ErrorMessage = string(p[off:])
}

func capabilityNames(f uint32) []string {
	type entry struct {
		bit  uint32
		name string
	}
	table := []entry{
		{0x00000001, "CLIENT_LONG_PASSWORD"},
		{0x00000002, "CLIENT_FOUND_ROWS"},
		{0x00000004, "CLIENT_LONG_FLAG"},
		{0x00000008, "CLIENT_CONNECT_WITH_DB"},
		{0x00000010, "CLIENT_NO_SCHEMA"},
		{0x00000020, "CLIENT_COMPRESS"},
		{0x00000040, "CLIENT_ODBC"},
		{0x00000080, "CLIENT_LOCAL_FILES"},
		{0x00000100, "CLIENT_IGNORE_SPACE"},
		{0x00000200, "CLIENT_PROTOCOL_41"},
		{0x00000400, "CLIENT_INTERACTIVE"},
		{0x00000800, "CLIENT_SSL"},
		{0x00001000, "CLIENT_IGNORE_SIGPIPE"},
		{0x00002000, "CLIENT_TRANSACTIONS"},
		{0x00004000, "CLIENT_RESERVED"},
		{0x00008000, "CLIENT_SECURE_CONNECTION"},
		{0x00010000, "CLIENT_MULTI_STATEMENTS"},
		{0x00020000, "CLIENT_MULTI_RESULTS"},
		{0x00040000, "CLIENT_PS_MULTI_RESULTS"},
		{0x00080000, "CLIENT_PLUGIN_AUTH"},
		{0x00100000, "CLIENT_CONNECT_ATTRS"},
		{0x00200000, "CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA"},
		{0x00400000, "CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS"},
		{0x00800000, "CLIENT_SESSION_TRACK"},
		{0x01000000, "CLIENT_DEPRECATE_EOF"},
		{0x40000000, "CLIENT_SSL_VERIFY_SERVER_CERT"},
	}
	var names []string
	for _, e := range table {
		if f&e.bit != 0 {
			names = append(names, e.name)
		}
	}
	return names
}

func statusFlagsNames(f uint16) []string {
	type entry struct {
		bit  uint16
		name string
	}
	table := []entry{
		{0x0001, "SERVER_STATUS_IN_TRANS"},
		{0x0002, "SERVER_STATUS_AUTOCOMMIT"},
		{0x0008, "SERVER_MORE_RESULTS_EXISTS"},
		{0x0010, "SERVER_QUERY_NO_GOOD_INDEX_USED"},
		{0x0020, "SERVER_QUERY_NO_INDEX_USED"},
	}
	var names []string
	for _, e := range table {
		if f&e.bit != 0 {
			names = append(names, e.name)
		}
	}
	return names
}

func authPluginDescription(name string) string {
	switch name {
	case "mysql_native_password":
		return "SHA1-based; offline-crackable hashcat mode 11200/300 (legacy default)"
	case "caching_sha2_password":
		return "SHA-256 cache-on-first-success (MySQL 8 default; modern)"
	case "sha256_password":
		return "RSA-encrypted; requires SSL or pubkey transfer"
	case "mysql_clear_password":
		return "password sent IN CLEARTEXT — MITM-capturable!"
	case "auth_socket":
		return "Unix socket peer-credentials — no password on wire"
	case "windows_native_password":
		return "Windows SSPI / NTLM integration"
	case "dialog":
		return "interactive multi-step (Percona PAM / MariaDB Cracklib)"
	case "ed25519":
		return "MariaDB Ed25519 signature-based auth"
	}
	return "uncatalogued auth plugin"
}

func errorCodeName(c int) string {
	switch c {
	case 1044:
		return "ER_DBACCESS_DENIED_ERROR"
	case 1045:
		return "ER_ACCESS_DENIED_ERROR (canonical brute-force feedback!)"
	case 1049:
		return "ER_BAD_DB_ERROR (canonical database enumeration)"
	case 1129:
		return "ER_HOST_IS_BLOCKED (server-side block after too many failures)"
	case 1130:
		return "ER_HOST_NOT_PRIVILEGED"
	case 1158:
		return "ER_NET_PACKET_TOO_LARGE"
	case 1251:
		return "ER_NOT_SUPPORTED_AUTH_MODE (auth plugin mismatch)"
	case 2059:
		return "ER_NO_AUTH_PLUGIN_FOUND"
	case 2061:
		return "ER_AUTH_PLUGIN_REQUIRES_SECURE_CONNECTION"
	case 2068:
		return "ER_NOT_IMPLEMENTED_FOR_CACHED_PASSWORD"
	case 3950:
		return "ER_NOT_VALID_PASSWORD"
	}
	return fmt.Sprintf("uncatalogued error code %d", c)
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
