// mysql.go — host-side MySQL / MariaDB packet decoder Spec.
// Wraps the internal/mysqldb walker.

package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xunholy/promptzero/internal/mysqldb"
	"github.com/xunholy/promptzero/internal/risk"
)

func init() { //nolint:gochecknoinits
	Register(mysqlDecodeSpec)
}

var mysqlDecodeSpec = Spec{
	Name: "mysql_decode",
	Description: "Decode a MySQL / MariaDB client/server protocol packet per " +
		"the MySQL documentation (Chapter 4: \"Client/Server Protocol\"). " +
		"TCP/3306 default; also seen via Unix sockets and MySQL Group " +
		"Replication on TCP/33061. Compatible with MariaDB which uses " +
		"the same wire format with minor extensions. The **largest open-" +
		"source database pentest target** — deployed everywhere from " +
		"cloud-managed MySQL (RDS / Aurora / Cloud SQL / Azure Database " +
		"/ PlanetScale) to bare-metal installations to containerized " +
		"side-cars to every shared-hosting cPanel deployment. Together " +
		"with `tds_decode` (v0.334) + `postgres_decode` (v0.335) this " +
		"completes the **database-protocol pentest trio** (MSSQL + " +
		"PostgreSQL + MySQL/MariaDB). The wire format leaks: **server " +
		"fingerprint via Handshake v10** (server_version string — " +
		"canonical MySQL version-fingerprint for CVE selection; 5.7.42 " +
		"/ 8.0.35-0ubuntu0.22.04.1 / 10.11.5-MariaDB / Percona Server " +
		"8.0.34-26); **authentication plugin negotiation** (Handshake " +
		"auth_plugin_name reveals security posture: **mysql_native_" +
		"password** = SHA1-based offline-crackable hashcat mode " +
		"11200/300 — legacy MySQL 5.7 / MariaDB default; **caching_sha2" +
		"_password** = modern MySQL 8 default; **sha256_password** = " +
		"RSA-encrypted requires SSL or pubkey transfer; **mysql_clear_" +
		"password** = password sent IN CLEARTEXT — MITM-capturable!; " +
		"**auth_socket** = Unix peer-credentials no password on wire; " +
		"**windows_native_password** = SSPI/NTLM; **dialog** = " +
		"interactive Percona PAM / MariaDB Cracklib); **TLS support " +
		"detection via CLIENT_SSL** (0x00000800 capability bit — server " +
		"advertises SSL support; client proceeding without TLS upgrade " +
		"sends username + auth data cleartext on TCP/3306); **cleartext " +
		"username + database via HandshakeResponse41** (canonical MySQL " +
		"credential-disclosure on TCP/3306 without TLS); **brute-force " +
		"feedback via ERR packet** (0xFF header + error code 1045 ER_" +
		"ACCESS_DENIED_ERROR = canonical wrong-password response; 1049 " +
		"ER_BAD_DB_ERROR = canonical database enumeration; 1129 ER_HOST" +
		"_IS_BLOCKED = server-side block after too many failures); " +
		"**connection ID disclosure** (4-byte LE — stable per-connection, " +
		"sequential allocation enumerable for traffic analysis). " +
		"Decodes:\n\n" +
		"- **4-byte packet header**: 3-byte LE length + 1-byte sequence " +
		"ID. Sequence resets to 0 at start of each command.\n" +
		"- **Handshake v10 body walker** (server → client, first packet, " +
		"sequence 0): protocol_version 0x0A + null-terminated server" +
		"_version + connection_id + capability flags + character set + " +
		"status flags + auth_plugin_name. Surfaces `protocol_version` + " +
		"`server_version` + `connection_id` + `capability_flags` + " +
		"`capability_names` + `status_flags` + `auth_plugin_name` + " +
		"`auth_plugin_description` (canonical security posture flag) + " +
		"`ssl_supported` (CLIENT_SSL bit).\n" +
		"- **HandshakeResponse41 body walker** (client → server, second " +
		"packet, sequence 1): capability flags + username + auth-data + " +
		"database + client_plugin_name. Surfaces `user_name` (cleartext!) " +
		"+ `database` (cleartext!) + `client_plugin_name` + " +
		"`auth_data_bytes` LENGTH only (privacy-preserving — never the " +
		"auth-data itself).\n" +
		"- **ERR packet walker** (server → client): 0xFF header + error " +
		"code + SQL state + error message. Surfaces `error_code` + " +
		"`error_code_name` + `sql_state` + `error_message`.\n" +
		"- **OK / EOF packet detection** — 0x00 / 0xFE headers surfaced " +
		"as `is_ok_packet` / `is_eof_packet` boolean classifications.\n" +
		"- **25-entry capability flags name table**: CLIENT_LONG_PASSWORD " +
		"/ CLIENT_FOUND_ROWS / CLIENT_LONG_FLAG / CLIENT_CONNECT_WITH_DB " +
		"/ CLIENT_NO_SCHEMA / CLIENT_COMPRESS / CLIENT_ODBC / CLIENT_" +
		"LOCAL_FILES / CLIENT_IGNORE_SPACE / CLIENT_PROTOCOL_41 / CLIENT" +
		"_INTERACTIVE / CLIENT_SSL (0x00800 TLS!) / CLIENT_IGNORE_SIGPIPE " +
		"/ CLIENT_TRANSACTIONS / CLIENT_RESERVED / CLIENT_SECURE_CONNECTION " +
		"/ CLIENT_MULTI_STATEMENTS / CLIENT_MULTI_RESULTS / CLIENT_PS_" +
		"MULTI_RESULTS / CLIENT_PLUGIN_AUTH / CLIENT_CONNECT_ATTRS / " +
		"CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA / CLIENT_CAN_HANDLE_" +
		"EXPIRED_PASSWORDS / CLIENT_SESSION_TRACK / CLIENT_DEPRECATE_EOF " +
		"/ CLIENT_SSL_VERIFY_SERVER_CERT.\n" +
		"- **5-entry status flags name table**: SERVER_STATUS_IN_TRANS / " +
		"SERVER_STATUS_AUTOCOMMIT / SERVER_MORE_RESULTS_EXISTS / SERVER" +
		"_QUERY_NO_GOOD_INDEX_USED / SERVER_QUERY_NO_INDEX_USED.\n" +
		"- **8-entry auth plugin description table** flagging security " +
		"posture: mysql_native_password (SHA1-weak / offline-crackable) " +
		"/ caching_sha2_password (modern MySQL 8 default) / sha256_" +
		"password (RSA — requires SSL) / mysql_clear_password (MITM-" +
		"capturable!) / auth_socket (Unix peer-credentials) / windows_" +
		"native_password (SSPI/NTLM) / dialog (interactive) / ed25519 " +
		"(MariaDB).\n" +
		"- **11-entry error code name table**: 1044 ER_DBACCESS_DENIED_" +
		"ERROR / 1045 ER_ACCESS_DENIED_ERROR (canonical brute-force " +
		"feedback!) / 1049 ER_BAD_DB_ERROR (canonical database " +
		"enumeration) / 1129 ER_HOST_IS_BLOCKED / 1130 ER_HOST_NOT_" +
		"PRIVILEGED / 1158 ER_NET_PACKET_TOO_LARGE / 1251 ER_NOT_SUPPORTED" +
		"_AUTH_MODE / 2059 ER_NO_AUTH_PLUGIN_FOUND / 2061 ER_AUTH_PLUGIN" +
		"_REQUIRES_SECURE_CONNECTION / 2068 ER_NOT_IMPLEMENTED_FOR_CACHED" +
		"_PASSWORD / 3950 ER_NOT_VALID_PASSWORD.\n\n" +
		"Pure offline parser — operators paste MySQL bytes (the TCP-" +
		"segment payload as hex; default TCP/3306) from a `tcpdump -X " +
		"port 3306` line or a Wireshark MySQL dissector view and get " +
		"the documented per-packet breakdown.\n\n" +
		"Out of scope (deferred): command-specific bodies (COM_QUERY " +
		"0x03 SQL text / COM_INIT_DB / COM_STMT_PREPARE + COM_STMT_" +
		"EXECUTE / COM_REGISTER_SLAVE replication / COM_BINLOG_DUMP / " +
		"COM_CHANGE_USER and 25+ other command bodies — decoder surfaces " +
		"packet header + command byte if present); result-set parsing " +
		"(TextResultSet + BinaryResultSet multi-packet state); binary-" +
		"protocol prepared-statement parameter marshalling; compressed " +
		"packet format (CLIENT_COMPRESS); SSL handshake (after CLIENT_" +
		"SSL set + SSLRequest sent, connection upgrades to TLS — handle " +
		"TLS strip first); caching_sha2_password full-auth-method " +
		"exchange (RSA-encrypted pubkey + scrambled-password sequences " +
		"with 0x04 / 0x02 markers); LOAD DATA LOCAL INFILE (0xFB header " +
		"abuse vector — detected but not decoded); MariaDB-specific " +
		"extensions (MARIADB_CLIENT_PROGRESS / MARIADB_CLIENT_COM_MULTI " +
		"/ MARIADB_CLIENT_STMT_BULK_OPERATIONS capability bits and " +
		"plugins ed25519 / parsec); XA / GTID / replication-specific " +
		"semantics (binlog packets, XA transaction prepare/commit/" +
		"rollback).\n\n" +
		"Source: docs/catalog/gap-analysis.md (database-protocol " +
		"foundational decoder — canonical MySQL / MariaDB pentest " +
		"dissector for credential capture + TLS-downgrade audit + " +
		"auth-method enumeration + version fingerprint + database " +
		"enumeration; completes the database-protocol pentest trio with " +
		"tds_decode + postgres_decode; common in DEF CON + Black Hat + " +
		"HITB + OffSec engagements + every sqlmap / hydra mysql / " +
		"nmap mysql-* NSE / metasploit mysql_login-driven MySQL attack " +
		"workflow). Wrap-vs-native: native — MySQL client/server " +
		"protocol is publicly documented (MySQL Reference Manual " +
		"Chapter 4); the packet format is a simple 3+1-byte length+" +
		"sequence header + payload; Handshake v10 + HandshakeResponse41 " +
		"+ ERR are deterministic struct walks with capability-bit-gated " +
		"optional fields; no crypto at the parse layer; password " +
		"contents NEVER decoded (auth_data_bytes length only — privacy-" +
		"preserving while flagging the simple-auth exposure).",
	Schema: json.RawMessage(`{
		"type":"object",
		"properties":{
			"hex":{"type":"string","description":"MySQL packet bytes as hex (the TCP-segment payload; default TCP/3306). Separators (':' '-' '_' whitespace) tolerated. '0x' prefix tolerated."}
		},
		"required":["hex"]
	}`),
	Required:  []string{"hex"},
	Risk:      risk.Low,
	Group:     GroupHostTools,
	AgentOnly: false,
	Handler:   mysqlDecodeHandler,
}

func mysqlDecodeHandler(_ context.Context, _ *Deps, p map[string]any) (string, error) {
	raw := str(p, "hex")
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("mysql_decode: 'hex' is required")
	}
	res, err := mysqldb.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("mysql_decode: %w", err)
	}
	out, _ := json.MarshalIndent(res, "", "  ")
	return string(out), nil
}
